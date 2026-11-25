use std::collections::BTreeMap;

use cbor2::Value;

use crate::{
    error::AslError,
    ids::{Hash32, Id128},
    protocol::{
        ConceptRef, TypedValue,
        cbor::{
            array, check_keys, concept_ref, concept_ref_value, decode_canonical, fields, finish,
            fixed_bytes, map, take, typed_value, typed_value_value, uint,
        },
    },
};

pub const MAX_ACT_BYTES: usize = 60 * 1024;
pub const MAX_ACT_NL_BYTES: usize = 32 * 1024;
pub const MAX_ACT_ACTION_ARGS: usize = 32;
pub const MAX_ACT_ATTACHMENTS: usize = 16;
pub const MAX_ACT_HOP: u32 = 1_024;
const MAX_TIME_MS: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActType {
    Inform,
    Ask,
    Request,
    Propose,
    Accept,
    Reject,
    Commit,
    Cancel,
    Ack,
    Clarify,
}

impl ActType {
    fn from_code(value: u64) -> Result<Self, AslError> {
        match value {
            0 => Ok(Self::Inform),
            1 => Ok(Self::Ask),
            2 => Ok(Self::Request),
            3 => Ok(Self::Propose),
            4 => Ok(Self::Accept),
            5 => Ok(Self::Reject),
            6 => Ok(Self::Commit),
            7 => Ok(Self::Cancel),
            8 => Ok(Self::Ack),
            9 => Ok(Self::Clarify),
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn code(self) -> u64 {
        match self {
            Self::Inform => 0,
            Self::Ask => 1,
            Self::Request => 2,
            Self::Propose => 3,
            Self::Accept => 4,
            Self::Reject => 5,
            Self::Commit => 6,
            Self::Cancel => 7,
            Self::Ack => 8,
            Self::Clarify => 9,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inform => "inform",
            Self::Ask => "ask",
            Self::Request => "request",
            Self::Propose => "propose",
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Commit => "commit",
            Self::Cancel => "cancel",
            Self::Ack => "ack",
            Self::Clarify => "clarify",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActAction {
    pub action_id: ConceptRef,
    pub args: BTreeMap<u32, TypedValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Act {
    pub message_id: Id128,
    pub conversation_id: Id128,
    pub act_type: ActType,
    pub reply_to: Option<Id128>,
    pub nl_body: Option<String>,
    pub action: Option<ActAction>,
    pub attachments: Vec<Hash32>,
    pub causal_root: Id128,
    pub hop: u32,
    pub expires_at_ms: Option<u64>,
}

impl Act {
    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if bytes.is_empty() || bytes.len() > MAX_ACT_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let mut fields = fields(decode_canonical(bytes)?)?;
        check_keys(&fields, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
        let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 1)?)?);
        let conversation_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
        let act_type = ActType::from_code(match take(&mut fields, 3)? {
            Value::Integer(value) => u64::try_from(value).map_err(|_| AslError::InvalidMessage)?,
            _ => return Err(AslError::InvalidMessage),
        })?;
        let reply_to = fields
            .remove(&4)
            .map(fixed_bytes::<16>)
            .transpose()?
            .map(Id128);
        let nl_body = fields
            .remove(&5)
            .map(|value| match value {
                Value::Text(value)
                    if !value.is_empty()
                        && value.len() <= MAX_ACT_NL_BYTES
                        && !value.as_bytes().contains(&0) =>
                {
                    Ok(value)
                }
                _ => Err(AslError::InvalidMessage),
            })
            .transpose()?;
        let action = fields.remove(&6).map(decode_action).transpose()?;
        let attachments = fields
            .remove(&7)
            .map(|value| {
                array(value, MAX_ACT_ATTACHMENTS)?
                    .into_iter()
                    .map(|value| fixed_bytes::<32>(value).map(Hash32))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let causal_root = Id128(fixed_bytes::<16>(take(&mut fields, 8)?)?);
        let hop = match take(&mut fields, 9)? {
            Value::Integer(value) => u32::try_from(value).map_err(|_| AslError::InvalidMessage)?,
            _ => return Err(AslError::InvalidMessage),
        };
        let expires_at_ms = fields
            .remove(&10)
            .map(|value| match value {
                Value::Integer(value) => u64::try_from(value).map_err(|_| AslError::InvalidMessage),
                _ => Err(AslError::InvalidMessage),
            })
            .transpose()?;
        finish(fields)?;
        let act = Self {
            message_id,
            conversation_id,
            act_type,
            reply_to,
            nl_body,
            action,
            attachments,
            causal_root,
            hop,
            expires_at_ms,
        };
        act.validate()?;
        Ok(act)
    }

    pub fn encode(&self) -> Result<Vec<u8>, AslError> {
        self.validate()?;
        let mut entries = vec![
            (1, Value::Bytes(self.message_id.0.to_vec())),
            (2, Value::Bytes(self.conversation_id.0.to_vec())),
            (3, uint(self.act_type.code())),
        ];
        if let Some(reply_to) = self.reply_to {
            entries.push((4, Value::Bytes(reply_to.0.to_vec())));
        }
        if let Some(body) = &self.nl_body {
            entries.push((5, Value::Text(body.clone())));
        }
        if let Some(action) = &self.action {
            entries.push((6, encode_action(action)));
        }
        if !self.attachments.is_empty() {
            entries.push((
                7,
                Value::Array(
                    self.attachments
                        .iter()
                        .map(|attachment| Value::Bytes(attachment.0.to_vec()))
                        .collect(),
                ),
            ));
        }
        entries.extend([
            (8, Value::Bytes(self.causal_root.0.to_vec())),
            (9, uint(u64::from(self.hop))),
        ]);
        if let Some(expires_at_ms) = self.expires_at_ms {
            entries.push((10, uint(expires_at_ms)));
        }
        let bytes = cbor2::to_canonical_vec(&map(entries)).map_err(|_| AslError::InvalidMessage)?;
        if bytes.len() > MAX_ACT_BYTES {
            return Err(AslError::InvalidMessage);
        }
        Self::decode(&bytes)?;
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), AslError> {
        if self.message_id.0 == [0; 16]
            || self.conversation_id.0 == [0; 16]
            || self.causal_root.0 == [0; 16]
            || self.hop > MAX_ACT_HOP
            || self.expires_at_ms.is_some_and(|value| value > MAX_TIME_MS)
            || self.nl_body.as_ref().is_some_and(|body| {
                body.is_empty() || body.len() > MAX_ACT_NL_BYTES || body.as_bytes().contains(&0)
            })
            || self.attachments.len() > MAX_ACT_ATTACHMENTS
            || self
                .attachments
                .iter()
                .enumerate()
                .any(|(index, item)| self.attachments[..index].contains(item))
            || (self.act_type == ActType::Request) != self.action.is_some()
        {
            return Err(AslError::InvalidMessage);
        }
        if let Some(action) = &self.action
            && (!action.action_id.is_known() || action.args.len() > MAX_ACT_ACTION_ARGS)
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }
}

fn decode_action(value: Value) -> Result<ActAction, AslError> {
    let mut fields = fields(value)?;
    check_keys(&fields, &[0, 1])?;
    let action_id = concept_ref(take(&mut fields, 0)?)?;
    let args = match take(&mut fields, 1)? {
        Value::Map(values) => {
            let mut args = BTreeMap::new();
            for (key, value) in values {
                let Value::Integer(key) = key else {
                    return Err(AslError::InvalidMessage);
                };
                let key = u32::try_from(key).map_err(|_| AslError::InvalidMessage)?;
                if args.insert(key, typed_value(value)?).is_some() {
                    return Err(AslError::InvalidMessage);
                }
            }
            args
        }
        _ => return Err(AslError::InvalidMessage),
    };
    finish(fields)?;
    Ok(ActAction { action_id, args })
}

fn encode_action(action: &ActAction) -> Value {
    map([
        (0, concept_ref_value(action.action_id)),
        (
            1,
            Value::Map(
                action
                    .args
                    .iter()
                    .map(|(key, value)| (uint(u64::from(*key)), typed_value_value(value)))
                    .collect(),
            ),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn act_text_is_confined_to_the_declared_body_and_round_trips() {
        let act = Act {
            message_id: Id128([1; 16]),
            conversation_id: Id128([2; 16]),
            act_type: ActType::Inform,
            reply_to: None,
            nl_body: Some("question and answer data".into()),
            action: None,
            attachments: vec![Hash32([3; 32])],
            causal_root: Id128([4; 16]),
            hop: 1,
            expires_at_ms: Some(10),
        };
        let bytes = act.encode().unwrap();
        assert_eq!(Act::decode(&bytes).unwrap(), act);
        assert!(bytes.windows(4).any(|window| window == b"data"));
    }

    #[test]
    fn request_requires_a_structured_action() {
        let act = Act {
            message_id: Id128([1; 16]),
            conversation_id: Id128([2; 16]),
            act_type: ActType::Request,
            reply_to: None,
            nl_body: Some("please do it".into()),
            action: None,
            attachments: Vec::new(),
            causal_root: Id128([3; 16]),
            hop: 0,
            expires_at_ms: None,
        };
        assert!(matches!(act.encode(), Err(AslError::InvalidMessage)));
    }
}
