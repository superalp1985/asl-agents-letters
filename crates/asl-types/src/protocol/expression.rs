use cbor2::Value as Cbor;
use serde_json::Value as Json;

use crate::{
    error::AslError,
    ids::{AgentId, Id128},
};

use super::cbor;

const MAX_DEPTH: usize = 8;
const MAX_NODES: usize = 256;
const MAX_ITEMS: usize = 16;
const MAX_SCALE: u8 = 18;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionLetter {
    pub message_id: Id128,
    pub root_task_id: Id128,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub expression: Expression,
}

/// A bounded, lexically validated syntax tree. Construct it with [`Self::from_json`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expression(Term);

impl Expression {
    /// Imports the tagged-array ASL expression syntax, not a complete letter.
    pub fn from_json(value: &Json) -> Result<Self, AslError> {
        Self::parse(Input::Json(value))
    }

    /// Exports the same tagged-array syntax accepted by [`Self::from_json`].
    pub fn to_json(&self) -> Json {
        self.0.encode()
    }

    pub(crate) fn is_definition_of(
        &self,
        authority: AgentId,
        namespace: u32,
        revision: u16,
        concept_id: u32,
        arity: u8,
    ) -> bool {
        let Term::MeaningIs(reference, declared_arity, _) = &self.0 else {
            return false;
        };
        reference.authority == authority
            && reference.namespace == namespace
            && reference.revision == revision
            && reference.id == concept_id
            && *declared_arity == arity
    }

    pub fn referenced_concepts(&self) -> Vec<(AgentId, u32, u16, u32)> {
        let mut references = Vec::new();
        self.0.collect_concepts(&mut references);
        references.sort_unstable_by_key(|(authority, namespace, revision, id)| {
            (authority.0, *namespace, *revision, *id)
        });
        references.dedup();
        references
    }

    pub(super) fn from_cbor(value: &Cbor) -> Result<Self, AslError> {
        Self::parse(Input::Cbor(value))
    }

    pub(super) fn to_cbor(&self) -> Cbor {
        self.0.encode()
    }

    fn parse(input: Input<'_>) -> Result<Self, AslError> {
        let mut budget = MAX_NODES;
        Term::parse(input, Scope::default(), MAX_DEPTH, &mut budget).map(Self)
    }
}

impl Term {
    fn collect_concepts(&self, output: &mut Vec<(AgentId, u32, u16, u32)>) {
        match self {
            Self::Concept(reference)
            | Self::Meaning(reference)
            | Self::MeaningIs(reference, _, _)
            | Self::Apply(reference, _) => {
                output.push((
                    reference.authority,
                    reference.namespace,
                    reference.revision,
                    reference.id,
                ));
                match self {
                    Self::MeaningIs(_, _, body) => body.collect_concepts(output),
                    Self::Apply(_, args) => {
                        for arg in args {
                            arg.collect_concepts(output);
                        }
                    }
                    _ => {}
                }
            }
            Self::Op(_, args) | Self::Tuple(args) => {
                for arg in args {
                    arg.collect_concepts(output);
                }
            }
            Self::Let(value, body) | Self::Define(_, value, body) | Self::If(value, body, _) => {
                value.collect_concepts(output);
                body.collect_concepts(output);
                if let Self::If(_, _, alternate) = self {
                    alternate.collect_concepts(output);
                }
            }
            Self::Call(_, args) => {
                for arg in args {
                    arg.collect_concepts(output);
                }
            }
            Self::Request(value) | Self::Assert(value) => value.collect_concepts(output),
            Self::Int(_) | Self::Decimal(_, _) | Self::Bool(_) | Self::Var(_) => {}
        }
    }
}

macro_rules! codes {
    ($type:ident { $($variant:ident = $code:literal, $name:literal;)+ }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum $type { $($variant,)+ }

        impl $type {
            fn parse(input: Input<'_>) -> Result<Self, AslError> {
                $(if input.is_code($code, $name) { return Ok(Self::$variant); })+
                Err(AslError::InvalidMessage)
            }

            fn encode<O: Output>(self) -> O {
                match self {
                    $(Self::$variant => O::code($code, $name),)+
                }
            }
        }
    };
}

codes!(Tag {
    Int = 0, "int";
    Decimal = 1, "decimal";
    Bool = 2, "bool";
    Op = 3, "op";
    Var = 4, "var";
    Let = 5, "let";
    Define = 6, "define";
    Call = 7, "call";
    If = 8, "if";
    Request = 9, "request";
    Assert = 10, "assert";
    Tuple = 11, "tuple";
    Concept = 12, "concept";
    Meaning = 13, "meaning";
    MeaningIs = 14, "meaning_is";
    Apply = 15, "apply";
});

codes!(Operator {
    Add = 0, "add";
    Sub = 1, "sub";
    Mul = 2, "mul";
    Div = 3, "div";
    Neg = 4, "neg";
    Eq = 5, "eq";
    Ne = 6, "ne";
    Lt = 7, "lt";
    Le = 8, "le";
    Gt = 9, "gt";
    Ge = 10, "ge";
    And = 11, "and";
    Or = 12, "or";
    Not = 13, "not";
});

impl Operator {
    fn arity(self) -> usize {
        match self {
            Self::Neg | Self::Not => 1,
            _ => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QualifiedConcept {
    authority: AgentId,
    namespace: u32,
    revision: u16,
    id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Term {
    Int(i64),
    Decimal(i64, u8),
    Bool(bool),
    Op(Operator, Vec<Term>),
    Var(u8),
    Let(Box<Term>, Box<Term>),
    Define(u8, Box<Term>, Box<Term>),
    Call(u8, Vec<Term>),
    If(Box<Term>, Box<Term>, Box<Term>),
    Request(Box<Term>),
    Assert(Box<Term>),
    Tuple(Vec<Term>),
    Concept(QualifiedConcept),
    Meaning(QualifiedConcept),
    MeaningIs(QualifiedConcept, u8, Box<Term>),
    Apply(QualifiedConcept, Vec<Term>),
}

#[derive(Clone, Copy, Default)]
struct Scope<'a> {
    vars: usize,
    symbol: Option<&'a Symbol<'a>>,
}

struct Symbol<'a> {
    arity: u8,
    outer: Option<&'a Symbol<'a>>,
}

impl Scope<'_> {
    fn symbol_arity(self, index: u8) -> Result<usize, AslError> {
        let mut symbol = self.symbol;
        for _ in 0..index {
            symbol = symbol.ok_or(AslError::InvalidMessage)?.outer;
        }
        Ok(usize::from(symbol.ok_or(AslError::InvalidMessage)?.arity))
    }
}

impl Term {
    fn parse<'a>(
        input: Input<'a>,
        scope: Scope<'_>,
        depth: usize,
        budget: &mut usize,
    ) -> Result<Self, AslError> {
        if depth == 0 || *budget == 0 {
            return Err(AslError::InvalidMessage);
        }
        *budget -= 1;
        let items = input.list(5)?;
        let (tag, fields) = items.split_first().ok_or(AslError::InvalidMessage)?;
        let child = |input, scope, budget: &mut _| Self::parse(input, scope, depth - 1, budget);
        let boxed = |input, scope, budget: &mut _| child(input, scope, budget).map(Box::new);
        let terms = |items: &[Input<'a>], budget: &mut _| {
            items
                .iter()
                .map(|&item| child(item, scope, budget))
                .collect::<Result<Vec<_>, _>>()
        };
        let concept = |input, budget: &mut _| match child(input, scope, budget)? {
            Self::Concept(reference) => Ok(reference),
            _ => Err(AslError::InvalidMessage),
        };
        let arity = |input: Input<'_>| match input.unsigned::<u8>()? {
            count if usize::from(count) <= MAX_ITEMS => Ok(count),
            _ => Err(AslError::InvalidMessage),
        };

        Ok(match (Tag::parse(*tag)?, fields) {
            (Tag::Int, [value]) => Self::Int(value.signed()?),
            (Tag::Decimal, [mantissa, scale]) => {
                let scale = scale.unsigned()?;
                if !(1..=MAX_SCALE).contains(&scale) {
                    return Err(AslError::InvalidMessage);
                }
                Self::Decimal(mantissa.signed()?, scale)
            }
            (Tag::Bool, [value]) => Self::Bool(value.boolean()?),
            (Tag::Op, [operator, args @ ..]) => {
                let operator = Operator::parse(*operator)?;
                if args.len() != operator.arity() {
                    return Err(AslError::InvalidMessage);
                }
                Self::Op(operator, terms(args, budget)?)
            }
            (Tag::Var, [index]) => {
                let index = index.unsigned()?;
                if usize::from(index) >= scope.vars {
                    return Err(AslError::InvalidMessage);
                }
                Self::Var(index)
            }
            (Tag::Let, [value, body]) => Self::Let(
                boxed(*value, scope, budget)?,
                boxed(
                    *body,
                    Scope {
                        vars: scope.vars + 1,
                        ..scope
                    },
                    budget,
                )?,
            ),
            (Tag::Define, [count, definition, body]) => {
                let count = arity(*count)?;
                let definition_scope = Scope {
                    vars: scope.vars + usize::from(count),
                    ..scope
                };
                let symbol = Symbol {
                    arity: count,
                    outer: scope.symbol,
                };
                Self::Define(
                    count,
                    boxed(*definition, definition_scope, budget)?,
                    boxed(
                        *body,
                        Scope {
                            symbol: Some(&symbol),
                            ..scope
                        },
                        budget,
                    )?,
                )
            }
            (Tag::Call, [index, args]) => {
                let index = index.unsigned()?;
                let arity = scope.symbol_arity(index)?;
                let args = args.list(arity)?;
                if args.len() != arity {
                    return Err(AslError::InvalidMessage);
                }
                Self::Call(index, terms(&args, budget)?)
            }
            (Tag::If, [condition, then, otherwise]) => Self::If(
                boxed(*condition, scope, budget)?,
                boxed(*then, scope, budget)?,
                boxed(*otherwise, scope, budget)?,
            ),
            (Tag::Request, [body]) => Self::Request(boxed(*body, scope, budget)?),
            (Tag::Assert, [body]) => Self::Assert(boxed(*body, scope, budget)?),
            (Tag::Tuple, [args]) => Self::Tuple(terms(&args.list(MAX_ITEMS)?, budget)?),
            (Tag::Concept, [authority, namespace, revision, id]) => {
                Self::Concept(QualifiedConcept {
                    authority: authority.authority()?,
                    namespace: namespace.unsigned()?,
                    revision: revision.unsigned()?,
                    id: id.unsigned()?,
                })
            }
            (Tag::Meaning, [reference]) => Self::Meaning(concept(*reference, budget)?),
            (Tag::MeaningIs, [reference, count, definition]) => {
                let count = arity(*count)?;
                let scope = Scope {
                    vars: usize::from(count),
                    symbol: None,
                };
                Self::MeaningIs(
                    concept(*reference, budget)?,
                    count,
                    boxed(*definition, scope, budget)?,
                )
            }
            (Tag::Apply, [reference, args]) => Self::Apply(
                concept(*reference, budget)?,
                terms(&args.list(MAX_ITEMS)?, budget)?,
            ),
            _ => return Err(AslError::InvalidMessage),
        })
    }

    fn encode<O: Output>(&self) -> O {
        fn list<O: Output>(terms: &[Term]) -> O {
            O::array(terms.iter().map(Term::encode).collect())
        }

        fn concept<O: Output>(value: &QualifiedConcept) -> O {
            O::array(vec![
                Tag::Concept.encode(),
                O::authority(value.authority),
                O::unsigned(value.namespace),
                O::unsigned(value.revision),
                O::unsigned(value.id),
            ])
        }

        O::array(match self {
            Self::Int(value) => vec![Tag::Int.encode(), O::signed(*value)],
            Self::Decimal(mantissa, scale) => {
                vec![
                    Tag::Decimal.encode(),
                    O::signed(*mantissa),
                    O::unsigned(*scale),
                ]
            }
            Self::Bool(value) => vec![Tag::Bool.encode(), O::boolean(*value)],
            Self::Op(op, args) => {
                let mut items = vec![Tag::Op.encode(), op.encode()];
                items.extend(args.iter().map(Term::encode));
                items
            }
            Self::Var(index) => vec![Tag::Var.encode(), O::unsigned(*index)],
            Self::Let(value, body) => vec![Tag::Let.encode(), value.encode(), body.encode()],
            Self::Define(arity, definition, body) => {
                vec![
                    Tag::Define.encode(),
                    O::unsigned(*arity),
                    definition.encode(),
                    body.encode(),
                ]
            }
            Self::Call(index, args) => vec![Tag::Call.encode(), O::unsigned(*index), list(args)],
            Self::If(condition, then, otherwise) => {
                vec![
                    Tag::If.encode(),
                    condition.encode(),
                    then.encode(),
                    otherwise.encode(),
                ]
            }
            Self::Request(body) => vec![Tag::Request.encode(), body.encode()],
            Self::Assert(body) => vec![Tag::Assert.encode(), body.encode()],
            Self::Tuple(args) => vec![Tag::Tuple.encode(), list(args)],
            Self::Concept(value) => return concept(value),
            Self::Meaning(value) => vec![Tag::Meaning.encode(), concept(value)],
            Self::MeaningIs(value, arity, definition) => {
                vec![
                    Tag::MeaningIs.encode(),
                    concept(value),
                    O::unsigned(*arity),
                    definition.encode(),
                ]
            }
            Self::Apply(value, args) => vec![Tag::Apply.encode(), concept(value), list(args)],
        })
    }
}

#[derive(Clone, Copy)]
enum Input<'a> {
    Cbor(&'a Cbor),
    Json(&'a Json),
}

impl<'a> Input<'a> {
    fn list(self, max: usize) -> Result<Vec<Self>, AslError> {
        match self {
            Self::Cbor(Cbor::Array(items)) if items.len() <= max => {
                Ok(items.iter().map(Self::Cbor).collect())
            }
            Self::Json(Json::Array(items)) if items.len() <= max => {
                Ok(items.iter().map(Self::Json).collect())
            }
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn is_code(self, code: u8, name: &str) -> bool {
        match self {
            Self::Cbor(_) => self.unsigned::<u8>().ok() == Some(code),
            Self::Json(value) => value.as_str() == Some(name),
        }
    }

    fn unsigned<T: TryFrom<u64>>(self) -> Result<T, AslError> {
        let value = match self {
            Self::Cbor(Cbor::Integer(value)) => u64::try_from(*value).ok(),
            Self::Json(value) => value.as_u64(),
            _ => None,
        };
        value
            .and_then(|value| T::try_from(value).ok())
            .ok_or(AslError::InvalidMessage)
    }

    fn signed(self) -> Result<i64, AslError> {
        let value = match self {
            Self::Cbor(Cbor::Integer(value)) => i64::try_from(*value).ok(),
            Self::Json(Json::String(value)) if value.len() <= 20 => value
                .parse::<i64>()
                .ok()
                .filter(|number| number.to_string() == *value),
            _ => None,
        };
        value.ok_or(AslError::InvalidMessage)
    }

    fn boolean(self) -> Result<bool, AslError> {
        match self {
            Self::Cbor(Cbor::Bool(value)) | Self::Json(Json::Bool(value)) => Ok(*value),
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn authority(self) -> Result<AgentId, AslError> {
        match self {
            Self::Cbor(Cbor::Bytes(value)) => value
                .as_slice()
                .try_into()
                .map(AgentId)
                .map_err(|_| AslError::InvalidMessage),
            Self::Json(Json::String(value)) if value.len() == 2 * AgentId::LENGTH => {
                fn nibble(byte: u8) -> Result<u8, AslError> {
                    match byte {
                        b'0'..=b'9' => Ok(byte - b'0'),
                        b'a'..=b'f' => Ok(byte - b'a' + 10),
                        _ => Err(AslError::InvalidMessage),
                    }
                }

                let mut bytes = [0; AgentId::LENGTH];
                for (byte, &[high, low]) in
                    bytes.iter_mut().zip(value.as_bytes().as_chunks::<2>().0)
                {
                    *byte = (nibble(high)? << 4) | nibble(low)?;
                }
                Ok(AgentId(bytes))
            }
            _ => Err(AslError::InvalidMessage),
        }
    }
}

trait Output {
    fn array(items: Vec<Self>) -> Self
    where
        Self: Sized;
    fn code(code: u8, name: &str) -> Self;
    fn unsigned(value: impl Into<u64>) -> Self;
    fn signed(value: i64) -> Self;
    fn boolean(value: bool) -> Self;
    fn authority(id: AgentId) -> Self;
}

impl Output for Cbor {
    fn array(items: Vec<Self>) -> Self {
        Self::Array(items)
    }
    fn code(code: u8, _: &str) -> Self {
        Self::unsigned(code)
    }
    fn unsigned(value: impl Into<u64>) -> Self {
        cbor::uint(value.into())
    }
    fn signed(value: i64) -> Self {
        Self::Integer(value.into())
    }
    fn boolean(value: bool) -> Self {
        Self::Bool(value)
    }
    fn authority(id: AgentId) -> Self {
        Self::Bytes(id.0.to_vec())
    }
}

impl Output for Json {
    fn array(items: Vec<Self>) -> Self {
        Self::Array(items)
    }
    fn code(_: u8, name: &str) -> Self {
        Self::String(name.to_owned())
    }
    fn unsigned(value: impl Into<u64>) -> Self {
        Self::from(value.into())
    }
    fn signed(value: i64) -> Self {
        Self::String(value.to_string())
    }
    fn boolean(value: bool) -> Self {
        Self::Bool(value)
    }
    fn authority(id: AgentId) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        Self::String(
            id.0.into_iter()
                .flat_map(|byte| {
                    [
                        char::from(HEX[usize::from(byte >> 4)]),
                        char::from(HEX[usize::from(byte & 15)]),
                    ]
                })
                .collect(),
        )
    }
}
