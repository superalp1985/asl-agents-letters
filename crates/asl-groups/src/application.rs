use asl_types::{
    error::AslError,
    ids::Id128,
    protocol::{Answer, Offer, Query, WireFrame, decode_control, encode_control},
};

/// The only ASL messages carried inside MLS application data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupApplication {
    Query(Query),
    Answer(Answer),
    Offer(Offer),
}

impl GroupApplication {
    pub fn message_id(&self) -> Id128 {
        match self {
            Self::Query(query) => query.message_id,
            Self::Answer(answer) => answer.message_id,
            Self::Offer(offer) => offer.message_id,
        }
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, AslError> {
        match decode_control(plaintext)? {
            WireFrame::Query(query) => Ok(Self::Query(query)),
            WireFrame::Answer(answer) => Ok(Self::Answer(answer)),
            WireFrame::Offer(offer) => Ok(Self::Offer(offer)),
            _ => Err(AslError::InvalidMessage),
        }
    }

    pub fn encode(self) -> Result<Vec<u8>, AslError> {
        encode_control(&match self {
            Self::Query(query) => WireFrame::Query(query),
            Self::Answer(answer) => WireFrame::Answer(answer),
            Self::Offer(offer) => WireFrame::Offer(offer),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(hex: &str) -> Vec<u8> {
        hex.split_ascii_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    #[test]
    fn application_reuses_canonical_semantic_frames_only() {
        for (index, hex) in [
            include_str!("../../../schemas/vectors/query-v1.hex"),
            include_str!("../../../schemas/vectors/answer-v1.hex"),
            include_str!("../../../schemas/vectors/offer-v1.hex"),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = fixture(hex);
            let message = GroupApplication::decode(&bytes).unwrap();
            assert!(matches!(
                (&message, index),
                (GroupApplication::Query(_), 0)
                    | (GroupApplication::Answer(_), 1)
                    | (GroupApplication::Offer(_), 2)
            ));
            assert_eq!(message.encode().unwrap(), bytes);
        }
        for bytes in [
            fixture(include_str!("../../../schemas/vectors/ack-v1.hex")),
            fixture(include_str!(
                "../../../schemas/vectors/fetch-request-v1.hex"
            )),
            fixture(include_str!(
                "../../../schemas/vectors/group-envelope-v1.hex"
            )),
            vec![0x62, b'h', b'i'],
        ] {
            assert!(GroupApplication::decode(&bytes).is_err());
        }
    }
}
