use std::{collections::BTreeMap, rc::Rc};

use asl_types::{
    error::AslError,
    ids::AgentId,
    protocol::{Expression, SemanticContextBundle, SemanticContextRef},
};
use serde_json::Value as Json;

use super::AuthenticatedSemanticContextBundle;

const MAX_EVALUATION_STEPS: usize = 4_096;
const MAX_EVALUATION_DEPTH: usize = 64;
const MAX_CONFORMANCE_STEPS: usize = 262_144;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticValue {
    Number(Rational),
    Boolean(bool),
    Concept(SemanticConcept),
    Tuple(Vec<Self>),
    Request(Box<Self>),
    Assertion(Box<Self>),
    Meaning(SemanticConcept),
    Definition(SemanticConcept, u8, Expression),
}

#[cfg(windows)]
impl SemanticValue {
    pub(crate) fn to_host_value(&self) -> Json {
        use serde_json::json;
        let concept = |value: &SemanticConcept| {
            json!([
                "concept",
                alloy_primitives::hex::encode(value.authority.0),
                value.namespace,
                value.revision,
                value.concept_id
            ])
        };
        match self {
            Self::Number(value) => json!([
                "rational",
                value.numerator().to_string(),
                value.denominator().to_string()
            ]),
            Self::Boolean(value) => json!(["bool", value]),
            Self::Concept(value) => concept(value),
            Self::Tuple(items) => json!([
                "tuple",
                items.iter().map(Self::to_host_value).collect::<Vec<_>>()
            ]),
            Self::Request(value) => json!(["request", value.to_host_value()]),
            Self::Assertion(value) => json!(["assert", value.to_host_value()]),
            Self::Meaning(value) => json!(["meaning", concept(value)]),
            Self::Definition(value, arity, term) => {
                json!(["meaning_is", concept(value), arity, term.to_json()])
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rational {
    numerator: i128,
    denominator: i128,
}

impl Rational {
    pub const fn integer(value: i128) -> Self {
        Self {
            numerator: value,
            denominator: 1,
        }
    }

    pub fn numerator(self) -> i128 {
        self.numerator
    }

    pub fn denominator(self) -> i128 {
        self.denominator
    }

    fn new(numerator: i128, denominator: i128) -> Option<Self> {
        if denominator == 0 {
            return None;
        }
        let (numerator, denominator) = if denominator < 0 {
            (numerator.checked_neg()?, denominator.checked_neg()?)
        } else {
            (numerator, denominator)
        };
        let divisor = gcd(numerator.unsigned_abs(), denominator as u128);
        let divisor = i128::try_from(divisor).ok()?;
        Some(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    fn add(self, other: Self) -> Option<Self> {
        let common =
            i128::try_from(gcd(self.denominator as u128, other.denominator as u128)).ok()?;
        let left_scale = other.denominator / common;
        let right_scale = self.denominator / common;
        Self::new(
            self.numerator
                .checked_mul(left_scale)?
                .checked_add(other.numerator.checked_mul(right_scale)?)?,
            self.denominator.checked_mul(left_scale)?,
        )
    }

    fn subtract(self, other: Self) -> Option<Self> {
        self.add(Self::new(
            other.numerator.checked_neg()?,
            other.denominator,
        )?)
    }

    fn multiply(self, other: Self) -> Option<Self> {
        let cancel_left = i128::try_from(gcd(
            self.numerator.unsigned_abs(),
            other.denominator as u128,
        ))
        .ok()?;
        let cancel_right = i128::try_from(gcd(
            other.numerator.unsigned_abs(),
            self.denominator as u128,
        ))
        .ok()?;
        Self::new(
            (self.numerator / cancel_left).checked_mul(other.numerator / cancel_right)?,
            (self.denominator / cancel_right).checked_mul(other.denominator / cancel_left)?,
        )
    }

    fn divide(self, other: Self) -> Option<Self> {
        self.multiply(Self::new(other.denominator, other.numerator)?)
    }

    fn compare(self, other: Self) -> Option<std::cmp::Ordering> {
        Some(
            self.numerator
                .checked_mul(other.denominator)?
                .cmp(&other.numerator.checked_mul(self.denominator)?),
        )
    }
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left.max(1)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SemanticConcept {
    pub authority: AgentId,
    pub namespace: u32,
    pub revision: u16,
    pub concept_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReadySemanticContextBundle {
    authenticated: AuthenticatedSemanticContextBundle,
    dependencies: Vec<SemanticContextRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticEvaluation {
    Value(SemanticValue),
    Unresolved,
    Invalid,
}

impl ConformanceReadySemanticContextBundle {
    pub fn bundle(&self) -> &SemanticContextBundle {
        self.authenticated.bundle()
    }

    pub fn context_ref(&self) -> SemanticContextRef {
        self.authenticated.context_ref()
    }

    pub fn dependencies(&self) -> &[SemanticContextRef] {
        &self.dependencies
    }

    pub fn encode_signed_bundle(&self) -> Result<Vec<u8>, AslError> {
        self.authenticated.signed_bundle().encode()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ContextKey {
    authority: [u8; 32],
    namespace: u32,
    revision: u16,
    digest: [u8; 32],
}

impl From<SemanticContextRef> for ContextKey {
    fn from(reference: SemanticContextRef) -> Self {
        Self {
            authority: reference.authority.0,
            namespace: reference.namespace,
            revision: reference.revision,
            digest: reference.digest.0,
        }
    }
}

type ContextMap = BTreeMap<ContextKey, AuthenticatedSemanticContextBundle>;

pub fn check_context_conformance(
    authenticated: AuthenticatedSemanticContextBundle,
    dependencies: Vec<AuthenticatedSemanticContextBundle>,
) -> Result<ConformanceReadySemanticContextBundle, AslError> {
    let target_key = ContextKey::from(authenticated.context_ref());
    let mut contexts = verified_context_map(std::iter::once(authenticated).chain(dependencies))?;
    let authenticated = contexts.remove(&target_key).ok_or(AslError::NotFound)?;
    Ok(ConformanceReadySemanticContextBundle {
        authenticated,
        dependencies: contexts
            .values()
            .map(|package| package.context_ref())
            .collect(),
    })
}

#[cfg(windows)]
pub(crate) fn interpret_contextual_expression(
    expression: &Expression,
    packages: Vec<AuthenticatedSemanticContextBundle>,
) -> Result<SemanticEvaluation, AslError> {
    let contexts = verified_context_map(packages)?;
    for (authority, namespace, revision, id) in expression.referenced_concepts() {
        let found = contexts.values().any(|package| {
            let bundle = package.bundle();
            (bundle.authority, bundle.namespace, bundle.revision)
                == (authority, namespace, revision)
                && bundle
                    .concepts
                    .binary_search_by_key(&id, |concept| concept.concept_id)
                    .is_ok()
        });
        if !found {
            return Ok(SemanticEvaluation::Unresolved);
        }
    }
    Ok(
        match evaluate_raw(expression, &Environment::default(), &contexts) {
            Ok(value) => SemanticEvaluation::Value(value),
            Err(EvaluationError::Unresolved) => SemanticEvaluation::Unresolved,
            Err(EvaluationError::Invalid) => SemanticEvaluation::Invalid,
        },
    )
}

fn verified_context_map(
    packages: impl IntoIterator<Item = AuthenticatedSemanticContextBundle>,
) -> Result<ContextMap, AslError> {
    let mut contexts = ContextMap::new();
    for package in packages {
        if contexts.len() >= 4_096 {
            return Err(AslError::QuotaExceeded);
        }
        let reference = package.context_ref();
        if package.bundle().kernel_revision != 1 {
            return Err(AslError::IncompatibleVersion);
        }
        let key = ContextKey::from(reference);
        if contexts.insert(key, package).is_some()
            || contexts.keys().any(|existing| {
                existing.authority == key.authority
                    && existing.namespace == key.namespace
                    && existing.revision == key.revision
                    && existing.digest != key.digest
            })
        {
            return Err(AslError::InvalidIdentity);
        }
    }

    let mut visit = Vec::new();
    let mut order = Vec::new();
    let mut marks = BTreeMap::<ContextKey, u8>::new();
    for key in contexts.keys().copied() {
        if marks.get(&key) == Some(&2) {
            continue;
        }
        visit.push((key, false));
        while let Some((current, exiting)) = visit.pop() {
            if exiting {
                marks.insert(current, 2);
                order.push(current);
                continue;
            }
            match marks.get(&current).copied() {
                Some(2) => continue,
                Some(1) => return Err(AslError::InvalidMessage),
                _ => {}
            }
            marks.insert(current, 1);
            visit.push((current, true));
            let package = contexts.get(&current).ok_or(AslError::InvalidIdentity)?;
            for dependency in package.bundle().dependencies.iter().rev() {
                let dependency_key = ContextKey::from(*dependency);
                if !contexts.contains_key(&dependency_key) {
                    return Err(AslError::NotFound);
                }
                match marks.get(&dependency_key).copied() {
                    Some(1) => return Err(AslError::InvalidMessage),
                    Some(2) => {}
                    _ => visit.push((dependency_key, false)),
                }
            }
        }
    }

    let mut conformance_steps = 0;
    for key in order {
        let package = contexts.get(&key).ok_or(AslError::InvalidIdentity)?;
        validate_conformance_vectors(package, &contexts, &mut conformance_steps)?;
    }
    Ok(contexts)
}

pub fn evaluate_semantic_expression(
    expression: &Expression,
    contexts: &[ConformanceReadySemanticContextBundle],
) -> SemanticEvaluation {
    let mut map = ContextMap::new();
    for context in contexts {
        let reference = context.context_ref();
        let key = ContextKey::from(reference);
        if map.insert(key, context.authenticated.clone()).is_some() {
            return SemanticEvaluation::Invalid;
        }
        if map.keys().any(|existing| {
            existing.authority == key.authority
                && existing.namespace == key.namespace
                && existing.revision == key.revision
                && existing.digest != key.digest
        }) {
            return SemanticEvaluation::Invalid;
        }
    }
    for context in contexts {
        for dependency in &context.dependencies {
            if !map.contains_key(&ContextKey::from(*dependency)) {
                return SemanticEvaluation::Unresolved;
            }
        }
    }
    match evaluate_raw(expression, &Environment::default(), &map) {
        Ok(value) => SemanticEvaluation::Value(value),
        Err(EvaluationError::Unresolved) => SemanticEvaluation::Unresolved,
        Err(EvaluationError::Invalid) => SemanticEvaluation::Invalid,
    }
}

fn validate_conformance_vectors(
    package: &AuthenticatedSemanticContextBundle,
    contexts: &ContextMap,
    steps: &mut usize,
) -> Result<(), AslError> {
    let env = Environment::default();
    for vector in &package.bundle().vectors {
        let mut budget = Budget::default();
        let arguments = vector
            .inputs
            .iter()
            .map(|expression| {
                evaluate_term(&expression.to_json(), &env, contexts, &mut budget, 0)
                    .map_err(|_| AslError::InvalidMessage)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let concept = SemanticConcept {
            authority: package.bundle().authority,
            namespace: package.bundle().namespace,
            revision: package.bundle().revision,
            concept_id: vector.concept_id,
        };
        let actual = apply_concept(concept, arguments, contexts, &mut budget, 0)
            .map_err(|_| AslError::InvalidMessage)?;
        let expected = evaluate_term(&vector.expected.to_json(), &env, contexts, &mut budget, 0)
            .map_err(|_| AslError::InvalidMessage)?;
        *steps += budget.remaining;
        if *steps > MAX_CONFORMANCE_STEPS {
            return Err(AslError::QuotaExceeded);
        }
        if actual != expected {
            return Err(AslError::InvalidIdentity);
        }
    }
    Ok(())
}

#[derive(Default)]
struct Budget {
    remaining: usize,
}

impl Budget {
    fn step(&mut self, depth: usize) -> Result<(), EvaluationError> {
        if depth > MAX_EVALUATION_DEPTH || self.remaining >= MAX_EVALUATION_STEPS {
            return Err(EvaluationError::Unresolved);
        }
        self.remaining += 1;
        Ok(())
    }

    fn charge_copy(&mut self, value: &SemanticValue, depth: usize) -> Result<(), EvaluationError> {
        self.step(depth)?;
        match value {
            SemanticValue::Tuple(items) => {
                for item in items {
                    self.charge_copy(item, depth + 1)?;
                }
            }
            SemanticValue::Request(value) | SemanticValue::Assertion(value) => {
                self.charge_copy(value, depth + 1)?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EvaluationError {
    Unresolved,
    Invalid,
}

#[derive(Clone, Default)]
struct Environment {
    variables: Vec<Rc<SemanticValue>>,
    symbols: Vec<Rc<LocalSymbol>>,
}

#[derive(Clone)]
struct LocalSymbol {
    arity: usize,
    definition: Json,
    captured_variables: Vec<Rc<SemanticValue>>,
    captured_symbols: Vec<Rc<LocalSymbol>>,
}

fn evaluate_raw(
    expression: &Expression,
    environment: &Environment,
    contexts: &ContextMap,
) -> Result<SemanticValue, EvaluationError> {
    evaluate_term(
        &expression.to_json(),
        environment,
        contexts,
        &mut Budget::default(),
        0,
    )
}

fn evaluate_term(
    term: &Json,
    environment: &Environment,
    contexts: &ContextMap,
    budget: &mut Budget,
    depth: usize,
) -> Result<SemanticValue, EvaluationError> {
    budget.step(depth)?;
    let fields = term.as_array().ok_or(EvaluationError::Invalid)?;
    let tag = fields
        .first()
        .and_then(Json::as_str)
        .ok_or(EvaluationError::Invalid)?;
    let field = |index: usize| fields.get(index).ok_or(EvaluationError::Invalid);
    let number = |index: usize| -> Result<i128, EvaluationError> {
        field(index)?
            .as_str()
            .ok_or(EvaluationError::Invalid)?
            .parse::<i64>()
            .map(i128::from)
            .map_err(|_| EvaluationError::Invalid)
    };
    let child = |index: usize, environment: &Environment, budget: &mut Budget, depth: usize| {
        evaluate_term(field(index)?, environment, contexts, budget, depth + 1)
    };
    let concept = || parse_concept(field(1)?);
    match tag {
        "int" => Ok(SemanticValue::Number(
            Rational::new(number(1)?, 1).ok_or(EvaluationError::Unresolved)?,
        )),
        "decimal" => {
            let mantissa = number(1)?;
            let scale = field(2)?
                .as_u64()
                .filter(|scale| (1..=18).contains(scale))
                .ok_or(EvaluationError::Invalid)?;
            let denominator = 10_i128
                .checked_pow(u32::try_from(scale).map_err(|_| EvaluationError::Invalid)?)
                .ok_or(EvaluationError::Unresolved)?;
            Ok(SemanticValue::Number(
                Rational::new(mantissa, denominator).ok_or(EvaluationError::Unresolved)?,
            ))
        }
        "bool" => field(1)?
            .as_bool()
            .map(SemanticValue::Boolean)
            .ok_or(EvaluationError::Invalid),
        "var" => {
            let index = field(1)?
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(EvaluationError::Invalid)?;
            let value = environment
                .variables
                .get(index)
                .ok_or(EvaluationError::Invalid)?;
            budget.charge_copy(value, depth)?;
            Ok(value.as_ref().clone())
        }
        "let" => {
            let value = child(1, environment, budget, depth)?;
            let mut nested = environment.clone();
            nested.variables.insert(0, Rc::new(value));
            evaluate_term(field(2)?, &nested, contexts, budget, depth + 1)
        }
        "define" => {
            let arity = field(1)?
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(EvaluationError::Invalid)?;
            let symbol = LocalSymbol {
                arity,
                definition: field(2)?.clone(),
                captured_variables: environment.variables.clone(),
                captured_symbols: environment.symbols.clone(),
            };
            let mut nested = environment.clone();
            nested.symbols.insert(0, Rc::new(symbol));
            evaluate_term(field(3)?, &nested, contexts, budget, depth + 1)
        }
        "call" => {
            let index = field(1)?
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(EvaluationError::Invalid)?;
            let symbol = environment
                .symbols
                .get(index)
                .ok_or(EvaluationError::Invalid)?;
            let arguments = field(2)?.as_array().ok_or(EvaluationError::Invalid)?;
            if arguments.len() != symbol.arity {
                return Err(EvaluationError::Invalid);
            }
            let values = arguments
                .iter()
                .map(|argument| evaluate_term(argument, environment, contexts, budget, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            let mut variables = values.into_iter().map(Rc::new).collect::<Vec<_>>();
            variables.extend(symbol.captured_variables.clone());
            let callee = Environment {
                variables,
                symbols: symbol.captured_symbols.clone(),
            };
            evaluate_term(&symbol.definition, &callee, contexts, budget, depth + 1)
        }
        "if" => match child(1, environment, budget, depth)? {
            SemanticValue::Boolean(true) => {
                evaluate_term(field(2)?, environment, contexts, budget, depth + 1)
            }
            SemanticValue::Boolean(false) => {
                evaluate_term(field(3)?, environment, contexts, budget, depth + 1)
            }
            _ => Err(EvaluationError::Invalid),
        },
        "request" => Ok(SemanticValue::Request(Box::new(child(
            1,
            environment,
            budget,
            depth,
        )?))),
        "assert" => Ok(SemanticValue::Assertion(Box::new(child(
            1,
            environment,
            budget,
            depth,
        )?))),
        "tuple" => {
            let items = field(1)?.as_array().ok_or(EvaluationError::Invalid)?;
            items
                .iter()
                .map(|item| evaluate_term(item, environment, contexts, budget, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(SemanticValue::Tuple)
        }
        "concept" => concept().map(SemanticValue::Concept),
        "meaning" => concept().map(SemanticValue::Meaning),
        "meaning_is" => Ok(SemanticValue::Definition(
            concept()?,
            field(2)?
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(EvaluationError::Invalid)?,
            Expression::from_json(field(3)?).map_err(|_| EvaluationError::Invalid)?,
        )),
        "apply" => {
            let concept = concept()?;
            let arguments = field(2)?.as_array().ok_or(EvaluationError::Invalid)?;
            let values = arguments
                .iter()
                .map(|argument| evaluate_term(argument, environment, contexts, budget, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            apply_concept(concept, values, contexts, budget, depth + 1)
        }
        "op" => {
            let operator = field(1)?.as_str().ok_or(EvaluationError::Invalid)?;
            let arguments = fields
                .get(2..)
                .ok_or(EvaluationError::Invalid)?
                .iter()
                .map(|argument| evaluate_term(argument, environment, contexts, budget, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            apply_operator(operator, &arguments)
        }
        _ => Err(EvaluationError::Invalid),
    }
}

fn apply_concept(
    concept: SemanticConcept,
    arguments: Vec<SemanticValue>,
    contexts: &ContextMap,
    budget: &mut Budget,
    depth: usize,
) -> Result<SemanticValue, EvaluationError> {
    let Some((_, package)) = contexts.iter().find(|(_, package)| {
        package.bundle().authority == concept.authority
            && package.bundle().namespace == concept.namespace
            && package.bundle().revision == concept.revision
    }) else {
        return Err(EvaluationError::Unresolved);
    };
    let definition = package
        .bundle()
        .concepts
        .binary_search_by_key(&concept.concept_id, |definition| definition.concept_id)
        .ok()
        .map(|index| &package.bundle().concepts[index])
        .ok_or(EvaluationError::Unresolved)?;
    if arguments.len() != usize::from(definition.arity) {
        return Err(EvaluationError::Invalid);
    }
    let json = definition.definition.to_json();
    let fields = json.as_array().ok_or(EvaluationError::Invalid)?;
    if fields.first().and_then(Json::as_str) != Some("meaning_is") {
        return Err(EvaluationError::Invalid);
    }
    let environment = Environment {
        variables: arguments.into_iter().map(Rc::new).collect(),
        symbols: Vec::new(),
    };
    evaluate_term(
        fields.get(3).ok_or(EvaluationError::Invalid)?,
        &environment,
        contexts,
        budget,
        depth + 1,
    )
}

fn parse_concept(term: &Json) -> Result<SemanticConcept, EvaluationError> {
    let fields = term.as_array().ok_or(EvaluationError::Invalid)?;
    if fields.len() != 5 || fields.first().and_then(Json::as_str) != Some("concept") {
        return Err(EvaluationError::Invalid);
    }
    let authority: [u8; 32] =
        alloy_primitives::hex::decode_to_array(fields[1].as_str().ok_or(EvaluationError::Invalid)?)
            .map_err(|_| EvaluationError::Invalid)?;
    Ok(SemanticConcept {
        authority: AgentId(authority),
        namespace: u32::try_from(fields[2].as_u64().ok_or(EvaluationError::Invalid)?)
            .map_err(|_| EvaluationError::Invalid)?,
        revision: u16::try_from(fields[3].as_u64().ok_or(EvaluationError::Invalid)?)
            .map_err(|_| EvaluationError::Invalid)?,
        concept_id: u32::try_from(fields[4].as_u64().ok_or(EvaluationError::Invalid)?)
            .map_err(|_| EvaluationError::Invalid)?,
    })
}

fn apply_operator(
    operator: &str,
    arguments: &[SemanticValue],
) -> Result<SemanticValue, EvaluationError> {
    let left = arguments.first().ok_or(EvaluationError::Invalid)?;
    match operator {
        "neg" => match left {
            SemanticValue::Number(value) => Ok(SemanticValue::Number(
                Rational::new(
                    value
                        .numerator
                        .checked_neg()
                        .ok_or(EvaluationError::Unresolved)?,
                    value.denominator,
                )
                .ok_or(EvaluationError::Unresolved)?,
            )),
            _ => Err(EvaluationError::Invalid),
        },
        "not" => match left {
            SemanticValue::Boolean(value) => Ok(SemanticValue::Boolean(!value)),
            _ => Err(EvaluationError::Invalid),
        },
        "eq" | "ne" => {
            let equal = left == arguments.get(1).ok_or(EvaluationError::Invalid)?;
            Ok(SemanticValue::Boolean(if operator == "eq" {
                equal
            } else {
                !equal
            }))
        }
        "and" | "or" => {
            let right = arguments.get(1).ok_or(EvaluationError::Invalid)?;
            match (left, right) {
                (SemanticValue::Boolean(left), SemanticValue::Boolean(right)) => {
                    Ok(SemanticValue::Boolean(if operator == "and" {
                        *left && *right
                    } else {
                        *left || *right
                    }))
                }
                _ => Err(EvaluationError::Invalid),
            }
        }
        "add" | "sub" | "mul" | "div" => {
            let right = arguments.get(1).ok_or(EvaluationError::Invalid)?;
            let (SemanticValue::Number(left), SemanticValue::Number(right)) = (left, right) else {
                return Err(EvaluationError::Invalid);
            };
            if operator == "div" && right.numerator == 0 {
                return Err(EvaluationError::Invalid);
            }
            let value = match operator {
                "add" => left.add(*right),
                "sub" => left.subtract(*right),
                "mul" => left.multiply(*right),
                _ => left.divide(*right),
            }
            .ok_or(EvaluationError::Unresolved)?;
            Ok(SemanticValue::Number(value))
        }
        "lt" | "le" | "gt" | "ge" => {
            let right = arguments.get(1).ok_or(EvaluationError::Invalid)?;
            let (SemanticValue::Number(left), SemanticValue::Number(right)) = (left, right) else {
                return Err(EvaluationError::Invalid);
            };
            let ordering = left.compare(*right).ok_or(EvaluationError::Unresolved)?;
            let value = match operator {
                "lt" => ordering.is_lt(),
                "le" => ordering.is_le(),
                "gt" => ordering.is_gt(),
                _ => ordering.is_ge(),
            };
            Ok(SemanticValue::Boolean(value))
        }
        _ => Err(EvaluationError::Invalid),
    }
}
