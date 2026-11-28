use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asl_groups::topology::{MAX_DIRECT_SHARD_MEMBERS, MAX_LAYERED_MEMBERS, plan_group_shards};
use asl_store::{
    Store,
    capacity::{CapacityClass, NewLocalCapacityMeasurement, StoredLocalCapacityMeasurement},
};
use asl_types::{error::AslError, ids::PeerId};
use cbor2::{Value, value::Integer};
use libp2p_identity::Keypair;

const MEASUREMENT_VERSION: u64 = 1;
const MEASUREMENT_METHOD: &str = "group-topology-planner-v1";
const CPU_SCORE_UNIT: &str = "10k-member-plans-per-second";
const CAPACITY_SCOPE: &str = "local-group-topology-planning";
const DIRECT_PLAN_BUDGET: Duration = Duration::from_millis(25);
const LAYERED_PLAN_BUDGET: Duration = Duration::from_millis(250);
const PROFILE_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1_000;
const PLANNER_REPETITIONS: usize = 3;
const DIRECT_SAMPLES: [usize; 6] = [16, 32, 64, 128, 256, 512];
const LAYERED_SAMPLES: [usize; 5] = [1_024, 2_048, 4_096, 8_192, MAX_LAYERED_MEMBERS];

pub use asl_store::capacity::CapacityClass as LocalCapacityClass;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerSample {
    pub members: usize,
    pub median_nanos: u64,
}

/// A local CPU profile for group topology planning, not network capacity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCapacityProfile {
    capacity_class: CapacityClass,
    direct_members: usize,
    gossip_members: usize,
    memory_bytes: Option<u64>,
    cpu_score: u32,
    network_bps: Option<u64>,
    available_parallelism: Option<u32>,
    measured_at_ms: u64,
    planner_samples: Vec<PlannerSample>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityBand {
    DirectBudget,
    ExtendedBudget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityRejection {
    MeasurementUnavailable,
    MeasurementStale,
    TimestampInFuture,
    InvalidProfile,
    InvalidMemberCount,
    CompileTimeLimitExceeded,
    MeasuredCapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityAdmission {
    Admitted(CapacityBand),
    Rejected(CapacityRejection),
}

/// Readiness of the local planner profile; this says nothing about RAM or network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileReadiness {
    Unavailable,
    Ready,
    Stale,
    TimestampInFuture,
    InvalidProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationStatus {
    Measured,
    NotMeasured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberCountRange {
    pub min: usize,
    pub max: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityMemberRange {
    pub direct_budget: Option<MemberCountRange>,
    pub extended_budget: Option<MemberCountRange>,
    pub hard_max_members: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityObservationReport {
    pub readiness: ProfileReadiness,
    pub scope: &'static str,
    pub method: &'static str,
    pub cpu_score_unit: &'static str,
    pub direct_budget_nanos: u64,
    pub extended_budget_nanos: u64,
    pub capacity_class: Option<CapacityClass>,
    pub measured_at_ms: Option<u64>,
    pub available_parallelism: Option<u32>,
    pub cpu_score: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub memory_status: ObservationStatus,
    pub network_bps: Option<u64>,
    pub network_status: ObservationStatus,
    pub member_range: Option<CapacityMemberRange>,
    pub planner_samples: Vec<PlannerSample>,
}

/// Runs `plan_group_shards` on synthetic peer IDs; it opens no sockets.
pub fn measure_local_capacity() -> Result<LocalCapacityProfile, AslError> {
    let measured_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    measure_local_capacity_at(measured_at_ms)
}

/// Reports whether the planner profile is usable for local admission decisions.
pub fn profile_readiness(profile: Option<&LocalCapacityProfile>, now_ms: u64) -> ProfileReadiness {
    let Some(profile) = profile else {
        return ProfileReadiness::Unavailable;
    };
    if !profile_has_valid_measurement(profile) {
        return ProfileReadiness::InvalidProfile;
    }
    let Some(age_ms) = now_ms.checked_sub(profile.measured_at_ms) else {
        return ProfileReadiness::TimestampInFuture;
    };
    if age_ms > PROFILE_MAX_AGE_MS {
        ProfileReadiness::Stale
    } else {
        ProfileReadiness::Ready
    }
}

/// Returns local planner-budget ranges, distinct from protocol or network limits.
pub fn profile_range(
    profile: &LocalCapacityProfile,
) -> Result<CapacityMemberRange, CapacityRejection> {
    if !profile_has_valid_measurement(profile) {
        return Err(CapacityRejection::InvalidProfile);
    }
    Ok(CapacityMemberRange {
        direct_budget: (profile.direct_members > 0).then_some(MemberCountRange {
            min: 1,
            max: profile.direct_members,
        }),
        extended_budget: (profile.gossip_members > profile.direct_members).then_some(
            MemberCountRange {
                min: profile.direct_members.saturating_add(1),
                max: profile.gossip_members,
            },
        ),
        hard_max_members: MAX_LAYERED_MEMBERS,
    })
}

/// Builds UI/runtime observations without converting unknown metrics to numbers.
pub fn report_capacity_observations(
    profile: Option<&LocalCapacityProfile>,
    now_ms: u64,
) -> CapacityObservationReport {
    let readiness = profile_readiness(profile, now_ms);
    let base = CapacityObservationReport {
        readiness,
        scope: CAPACITY_SCOPE,
        method: MEASUREMENT_METHOD,
        cpu_score_unit: CPU_SCORE_UNIT,
        direct_budget_nanos: DIRECT_PLAN_BUDGET.as_nanos() as u64,
        extended_budget_nanos: LAYERED_PLAN_BUDGET.as_nanos() as u64,
        capacity_class: None,
        measured_at_ms: None,
        available_parallelism: None,
        cpu_score: None,
        memory_bytes: None,
        memory_status: ObservationStatus::NotMeasured,
        network_bps: None,
        network_status: ObservationStatus::NotMeasured,
        member_range: None,
        planner_samples: Vec::new(),
    };
    let Some(profile) = profile else {
        return base;
    };
    CapacityObservationReport {
        capacity_class: Some(profile.capacity_class),
        measured_at_ms: Some(profile.measured_at_ms),
        available_parallelism: profile.available_parallelism,
        cpu_score: Some(profile.cpu_score),
        memory_bytes: profile.memory_bytes,
        memory_status: if profile.memory_bytes.is_some() {
            ObservationStatus::Measured
        } else {
            ObservationStatus::NotMeasured
        },
        network_bps: profile.network_bps,
        network_status: if profile.network_bps.is_some() {
            ObservationStatus::Measured
        } else {
            ObservationStatus::NotMeasured
        },
        member_range: profile_range(profile).ok(),
        planner_samples: profile.planner_samples.clone(),
        ..base
    }
}

fn measure_local_capacity_at(measured_at_ms: u64) -> Result<LocalCapacityProfile, AslError> {
    let parallelism = std::thread::available_parallelism()
        .ok()
        .and_then(|value| u32::try_from(value.get()).ok());
    let synthetic_members = synthetic_members(MAX_LAYERED_MEMBERS)?;
    let mut planner_samples = Vec::with_capacity(DIRECT_SAMPLES.len() + LAYERED_SAMPLES.len());

    for members in DIRECT_SAMPLES.into_iter().chain(LAYERED_SAMPLES) {
        planner_samples.push(measure_planner(
            &synthetic_members[..members],
            MAX_DIRECT_SHARD_MEMBERS,
        )?);
    }

    let (direct_members, gossip_members) = measured_member_limits(&planner_samples);
    let cpu_score = measured_cpu_score(&planner_samples).ok_or(AslError::InvalidPolicyState)?;

    Ok(LocalCapacityProfile {
        capacity_class: capacity_class(gossip_members),
        direct_members,
        gossip_members,
        memory_bytes: None,
        cpu_score,
        network_bps: None,
        available_parallelism: parallelism,
        measured_at_ms,
        planner_samples,
    })
}

/// Persists one local measurement and its method/scope metadata in the Store.
pub fn persist_local_capacity(
    store: &mut Store,
    profile: &LocalCapacityProfile,
) -> Result<(), AslError> {
    let parameters_cbor = encode_parameters(profile)?;
    store.record_local_capacity_measurement(&NewLocalCapacityMeasurement {
        capacity_class: profile.capacity_class,
        direct_members: u64::try_from(profile.direct_members)
            .map_err(|_| AslError::InvalidMessage)?,
        gossip_members: u64::try_from(profile.gossip_members)
            .map_err(|_| AslError::InvalidMessage)?,
        memory_bytes: profile.memory_bytes,
        cpu_score: profile.cpu_score,
        network_bps: profile.network_bps,
        parameters_cbor,
        measured_at_ms: profile.measured_at_ms,
    })
}

/// Reads and validates the latest typed local profile, if one exists.
pub fn latest_local_capacity(store: &Store) -> Result<Option<LocalCapacityProfile>, AslError> {
    store
        .latest_local_capacity_measurement()?
        .map(profile_from_record)
        .transpose()
}

/// Admits only group sizes within the fresh local planner benchmark and hard cap.
pub fn admit_group_size(
    profile: Option<&LocalCapacityProfile>,
    proposed_members: usize,
    now_ms: u64,
) -> CapacityAdmission {
    if proposed_members == 0 {
        return CapacityAdmission::Rejected(CapacityRejection::InvalidMemberCount);
    }
    if proposed_members > MAX_LAYERED_MEMBERS {
        return CapacityAdmission::Rejected(CapacityRejection::CompileTimeLimitExceeded);
    }
    let Some(profile) = profile else {
        return CapacityAdmission::Rejected(CapacityRejection::MeasurementUnavailable);
    };
    match profile_readiness(Some(profile), now_ms) {
        ProfileReadiness::Unavailable => {
            return CapacityAdmission::Rejected(CapacityRejection::MeasurementUnavailable);
        }
        ProfileReadiness::Stale => {
            return CapacityAdmission::Rejected(CapacityRejection::MeasurementStale);
        }
        ProfileReadiness::TimestampInFuture => {
            return CapacityAdmission::Rejected(CapacityRejection::TimestampInFuture);
        }
        ProfileReadiness::InvalidProfile => {
            return CapacityAdmission::Rejected(CapacityRejection::InvalidProfile);
        }
        ProfileReadiness::Ready => {}
    }
    if proposed_members > profile.gossip_members {
        return CapacityAdmission::Rejected(CapacityRejection::MeasuredCapacityExceeded);
    }
    CapacityAdmission::Admitted(if proposed_members <= profile.direct_members {
        CapacityBand::DirectBudget
    } else {
        CapacityBand::ExtendedBudget
    })
}

fn synthetic_members(count: usize) -> Result<Vec<PeerId>, AslError> {
    (0..count)
        .map(|index| {
            let mut seed = [0; 32];
            let index = u64::try_from(index + 1).map_err(|_| AslError::InvalidMessage)?;
            seed[..8].copy_from_slice(&index.to_be_bytes());
            let key = Keypair::ed25519_from_bytes(seed).map_err(|_| AslError::InvalidMessage)?;
            PeerId::from_bytes(key.public().to_peer_id().to_bytes())
                .map_err(|_| AslError::InvalidMessage)
        })
        .collect()
}

fn measure_planner(members: &[PeerId], max_per_shard: usize) -> Result<PlannerSample, AslError> {
    let mut timings = Vec::with_capacity(PLANNER_REPETITIONS);
    for _ in 0..PLANNER_REPETITIONS {
        let started = Instant::now();
        let plan = plan_group_shards(members.to_vec(), max_per_shard)?;
        std::hint::black_box(plan);
        timings.push(started.elapsed().as_nanos().clamp(1, u64::MAX as u128) as u64);
    }
    timings.sort_unstable();
    Ok(PlannerSample {
        members: members.len(),
        median_nanos: timings[timings.len() / 2],
    })
}

fn capacity_class(gossip_members: usize) -> CapacityClass {
    match gossip_members {
        0..=MAX_DIRECT_SHARD_MEMBERS => CapacityClass::Small,
        513..=2_048 => CapacityClass::Medium,
        2_049..=8_192 => CapacityClass::Large,
        _ => CapacityClass::Layered,
    }
}

fn measured_member_limits(samples: &[PlannerSample]) -> (usize, usize) {
    let direct_members = samples
        .iter()
        .filter(|sample| sample.members <= MAX_DIRECT_SHARD_MEMBERS)
        .take_while(|sample| sample.median_nanos <= DIRECT_PLAN_BUDGET.as_nanos() as u64)
        .last()
        .map_or(0, |sample| sample.members);
    let gossip_members = samples
        .iter()
        .take_while(|sample| sample.median_nanos <= LAYERED_PLAN_BUDGET.as_nanos() as u64)
        .last()
        .map_or(0, |sample| sample.members);
    (direct_members, gossip_members)
}

fn measured_cpu_score(samples: &[PlannerSample]) -> Option<u32> {
    let largest_sample = samples.iter().max_by_key(|sample| sample.members)?;
    Some(
        (1_000_000_000u128 / u128::from(largest_sample.median_nanos.max(1))).clamp(1, 1_000_000)
            as u32,
    )
}

fn profile_has_valid_measurement(profile: &LocalCapacityProfile) -> bool {
    let expected_members = DIRECT_SAMPLES.into_iter().chain(LAYERED_SAMPLES);
    if profile.planner_samples.len() != DIRECT_SAMPLES.len() + LAYERED_SAMPLES.len()
        || !profile
            .planner_samples
            .iter()
            .zip(expected_members)
            .all(|(sample, expected)| sample.members == expected && sample.median_nanos > 0)
    {
        return false;
    }
    let (direct_members, gossip_members) = measured_member_limits(&profile.planner_samples);
    profile.direct_members == direct_members
        && profile.gossip_members == gossip_members
        && profile.direct_members <= MAX_DIRECT_SHARD_MEMBERS
        && profile.direct_members <= profile.gossip_members
        && profile.gossip_members <= MAX_LAYERED_MEMBERS
        && measured_cpu_score(&profile.planner_samples) == Some(profile.cpu_score)
        && profile.memory_bytes.is_none()
        && profile.network_bps.is_none()
        && profile.available_parallelism.is_none_or(|value| value > 0)
        && capacity_class(profile.gossip_members) == profile.capacity_class
}

fn encode_parameters(profile: &LocalCapacityProfile) -> Result<Vec<u8>, AslError> {
    let samples = profile
        .planner_samples
        .iter()
        .map(|sample| {
            Ok(Value::Array(vec![
                uint(u64::try_from(sample.members).map_err(|_| AslError::InvalidMessage)?),
                uint(sample.median_nanos),
            ]))
        })
        .collect::<Result<Vec<_>, AslError>>()?;
    let parallelism = profile
        .available_parallelism
        .map(u64::from)
        .map(uint)
        .unwrap_or(Value::Null);
    cbor2::to_canonical_vec(&Value::Map(vec![
        (uint(0), uint(MEASUREMENT_VERSION)),
        (uint(1), Value::Text(MEASUREMENT_METHOD.to_owned())),
        (uint(2), parallelism),
        (uint(3), Value::Bool(profile.memory_bytes.is_some())),
        (uint(4), Value::Bool(profile.network_bps.is_some())),
        (uint(5), Value::Array(samples)),
        (
            uint(6),
            uint(DIRECT_PLAN_BUDGET.as_nanos().min(u64::MAX as u128) as u64),
        ),
        (
            uint(7),
            uint(LAYERED_PLAN_BUDGET.as_nanos().min(u64::MAX as u128) as u64),
        ),
        (uint(8), Value::Text(CPU_SCORE_UNIT.to_owned())),
        (uint(9), Value::Text(CAPACITY_SCOPE.to_owned())),
    ]))
    .map_err(|_| AslError::InvalidPolicyState)
}

struct CapacityParameters {
    available_parallelism: Option<u32>,
    memory_measured: bool,
    network_measured: bool,
    planner_samples: Vec<PlannerSample>,
}

fn decode_parameters(bytes: &[u8]) -> Result<CapacityParameters, AslError> {
    let value: Value = cbor2::from_slice(bytes).map_err(|_| AslError::InvalidDatabase)?;
    let Value::Map(fields) = value else {
        return Err(AslError::InvalidDatabase);
    };
    if fields.len() != 10
        || text(field(&fields, 1)?)? != MEASUREMENT_METHOD
        || text(field(&fields, 8)?)? != CPU_SCORE_UNIT
        || text(field(&fields, 9)?)? != CAPACITY_SCOPE
        || as_u64(field(&fields, 0)?)? != MEASUREMENT_VERSION
        || as_u64(field(&fields, 6)?)? != DIRECT_PLAN_BUDGET.as_nanos() as u64
        || as_u64(field(&fields, 7)?)? != LAYERED_PLAN_BUDGET.as_nanos() as u64
    {
        return Err(AslError::InvalidDatabase);
    }
    let available_parallelism = match field(&fields, 2)? {
        Value::Null => None,
        value => Some(u32::try_from(as_u64(value)?).map_err(|_| AslError::InvalidDatabase)?),
    };
    let memory_measured = as_bool(field(&fields, 3)?)?;
    let network_measured = as_bool(field(&fields, 4)?)?;
    if memory_measured || network_measured {
        return Err(AslError::InvalidDatabase);
    }
    let Value::Array(samples) = field(&fields, 5)? else {
        return Err(AslError::InvalidDatabase);
    };
    if samples.len() > DIRECT_SAMPLES.len() + LAYERED_SAMPLES.len() {
        return Err(AslError::InvalidDatabase);
    }
    let planner_samples = samples
        .iter()
        .map(|value| {
            let Value::Array(pair) = value else {
                return Err(AslError::InvalidDatabase);
            };
            if pair.len() != 2 {
                return Err(AslError::InvalidDatabase);
            }
            let members =
                usize::try_from(as_u64(&pair[0])?).map_err(|_| AslError::InvalidDatabase)?;
            let median_nanos = as_u64(&pair[1])?;
            if members == 0 || members > MAX_LAYERED_MEMBERS || median_nanos == 0 {
                return Err(AslError::InvalidDatabase);
            }
            Ok(PlannerSample {
                members,
                median_nanos,
            })
        })
        .collect::<Result<Vec<_>, AslError>>()?;
    Ok(CapacityParameters {
        available_parallelism,
        memory_measured,
        network_measured,
        planner_samples,
    })
}

fn profile_from_record(
    record: StoredLocalCapacityMeasurement,
) -> Result<LocalCapacityProfile, AslError> {
    let parameters = decode_parameters(&record.parameters_cbor)?;
    let memory_bytes = measured_option(parameters.memory_measured, record.memory_bytes_column)?;
    let network_bps = measured_option(parameters.network_measured, record.network_bps_column)?;
    let direct_members =
        usize::try_from(record.direct_members).map_err(|_| AslError::InvalidDatabase)?;
    let gossip_members =
        usize::try_from(record.gossip_members).map_err(|_| AslError::InvalidDatabase)?;
    if direct_members > gossip_members
        || gossip_members > MAX_LAYERED_MEMBERS
        || capacity_class(gossip_members) != record.capacity_class
    {
        return Err(AslError::InvalidDatabase);
    }
    let profile = LocalCapacityProfile {
        capacity_class: record.capacity_class,
        direct_members,
        gossip_members,
        memory_bytes,
        cpu_score: record.cpu_score,
        network_bps,
        available_parallelism: parameters.available_parallelism,
        measured_at_ms: record.measured_at_ms,
        planner_samples: parameters.planner_samples,
    };
    if !profile_has_valid_measurement(&profile) {
        return Err(AslError::InvalidDatabase);
    }
    Ok(profile)
}

fn measured_option(is_measured: bool, column_value: u64) -> Result<Option<u64>, AslError> {
    match (is_measured, column_value) {
        (false, 0) => Ok(None),
        (true, value) => Ok(Some(value)),
        (false, _) => Err(AslError::InvalidDatabase),
    }
}

fn field(fields: &[(Value, Value)], key: u64) -> Result<&Value, AslError> {
    let key = uint(key);
    let mut matches = fields.iter().filter(|(field, _)| field == &key);
    let value = matches.next().map(|(_, value)| value);
    if matches.next().is_some() {
        return Err(AslError::InvalidDatabase);
    }
    value.ok_or(AslError::InvalidDatabase)
}

fn text(value: &Value) -> Result<&str, AslError> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(AslError::InvalidDatabase),
    }
}

fn as_bool(value: &Value) -> Result<bool, AslError> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(AslError::InvalidDatabase),
    }
}

fn as_u64(value: &Value) -> Result<u64, AslError> {
    match value {
        Value::Integer(value) => u64::try_from(*value).map_err(|_| AslError::InvalidDatabase),
        _ => Err(AslError::InvalidDatabase),
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> LocalCapacityProfile {
        let planner_samples = DIRECT_SAMPLES
            .into_iter()
            .chain(LAYERED_SAMPLES)
            .map(|members| PlannerSample {
                members,
                median_nanos: if members <= 128 {
                    10_000_000
                } else if members <= 2048 {
                    50_000_000
                } else {
                    300_000_000
                },
            })
            .collect();
        LocalCapacityProfile {
            capacity_class: CapacityClass::Medium,
            direct_members: 128,
            gossip_members: 2048,
            memory_bytes: None,
            cpu_score: 3,
            network_bps: None,
            available_parallelism: Some(8),
            measured_at_ms: 1_000,
            planner_samples,
        }
    }

    #[test]
    fn admission_uses_measured_bands_and_preserves_the_compile_time_limit() {
        let profile = profile();

        assert_eq!(
            admit_group_size(Some(&profile), 128, 2_000),
            CapacityAdmission::Admitted(CapacityBand::DirectBudget)
        );
        assert_eq!(
            admit_group_size(Some(&profile), 512, 2_000),
            CapacityAdmission::Admitted(CapacityBand::ExtendedBudget)
        );
        assert_eq!(
            admit_group_size(Some(&profile), 2049, 2_000),
            CapacityAdmission::Rejected(CapacityRejection::MeasuredCapacityExceeded)
        );
        assert_eq!(
            admit_group_size(Some(&profile), MAX_LAYERED_MEMBERS + 1, 2_000),
            CapacityAdmission::Rejected(CapacityRejection::CompileTimeLimitExceeded)
        );
    }

    #[test]
    fn admission_fails_closed_without_a_fresh_measurement() {
        let profile = profile();

        assert_eq!(
            admit_group_size(None, 32, 2_000),
            CapacityAdmission::Rejected(CapacityRejection::MeasurementUnavailable)
        );
        assert_eq!(
            admit_group_size(Some(&profile), 32, 1_000 + PROFILE_MAX_AGE_MS + 1),
            CapacityAdmission::Rejected(CapacityRejection::MeasurementStale)
        );
        assert_eq!(
            admit_group_size(Some(&profile), 0, 2_000),
            CapacityAdmission::Rejected(CapacityRejection::InvalidMemberCount)
        );
    }

    #[test]
    fn capacity_metadata_keeps_unmeasured_memory_and_network_distinct_from_zero() {
        let profile = profile();
        let encoded = encode_parameters(&profile).unwrap();
        let decoded = decode_parameters(&encoded).unwrap();

        assert_eq!(decoded.available_parallelism, Some(8));
        assert!(!decoded.memory_measured);
        assert!(!decoded.network_measured);
    }

    #[test]
    fn public_range_and_report_keep_the_measurement_scope_explicit() {
        let profile = profile();
        assert_eq!(
            profile_range(&profile).unwrap(),
            CapacityMemberRange {
                direct_budget: Some(MemberCountRange { min: 1, max: 128 }),
                extended_budget: Some(MemberCountRange {
                    min: 129,
                    max: 2048,
                }),
                hard_max_members: MAX_LAYERED_MEMBERS,
            }
        );

        let report = report_capacity_observations(Some(&profile), 2_000);
        assert_eq!(report.readiness, ProfileReadiness::Ready);
        assert_eq!(report.scope, "local-group-topology-planning");
        assert_eq!(report.method, "group-topology-planner-v1");
        assert_eq!(report.direct_budget_nanos, 25_000_000);
        assert_eq!(report.extended_budget_nanos, 250_000_000);
        assert_eq!(report.capacity_class, Some(CapacityClass::Medium));
        assert_eq!(report.memory_status, ObservationStatus::NotMeasured);
        assert_eq!(report.network_status, ObservationStatus::NotMeasured);
        assert_eq!(report.network_bps, None);
    }

    #[test]
    fn readiness_reports_future_timestamps_and_invalid_ranges() {
        let mut profile = profile();
        assert_eq!(
            profile_readiness(Some(&profile), 999),
            ProfileReadiness::TimestampInFuture
        );

        profile.direct_members = 4096;
        assert_eq!(
            profile_readiness(Some(&profile), 2_000),
            ProfileReadiness::InvalidProfile
        );
    }

    #[test]
    fn capacity_thresholds_stop_at_the_first_failed_sample() {
        let samples = [
            PlannerSample {
                members: 16,
                median_nanos: 5_000_000,
            },
            PlannerSample {
                members: 32,
                median_nanos: 30_000_000,
            },
            PlannerSample {
                members: 64,
                median_nanos: 1_000_000,
            },
            PlannerSample {
                members: 128,
                median_nanos: 300_000_000,
            },
        ];

        assert_eq!(measured_member_limits(&samples), (16, 64));
    }
}
