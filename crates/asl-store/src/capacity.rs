use asl_types::error::AslError;
use rusqlite::{OptionalExtension, params};

use crate::{Store, database_error};

const MAX_CAPACITY_MEASUREMENTS: i64 = 64;
const MAX_MEMBER_COUNT: u64 = 10_000_000;
const MAX_RESOURCE_BYTES: u64 = 1_099_511_627_776;
const MAX_PARAMETERS_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityClass {
    Small,
    Medium,
    Large,
    Layered,
}

impl CapacityClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Layered => "layered",
        }
    }

    fn parse(value: &str) -> Result<Self, AslError> {
        match value {
            "small" => Ok(Self::Small),
            "medium" => Ok(Self::Medium),
            "large" => Ok(Self::Large),
            "layered" => Ok(Self::Layered),
            _ => Err(AslError::InvalidDatabase),
        }
    }
}

pub struct NewLocalCapacityMeasurement {
    pub capacity_class: CapacityClass,
    pub direct_members: u64,
    pub gossip_members: u64,
    pub memory_bytes: Option<u64>,
    pub cpu_score: u32,
    pub network_bps: Option<u64>,
    pub parameters_cbor: Vec<u8>,
    pub measured_at_ms: u64,
}

pub struct StoredLocalCapacityMeasurement {
    pub measurement_id: i64,
    pub capacity_class: CapacityClass,
    pub direct_members: u64,
    pub gossip_members: u64,
    pub memory_bytes_column: u64,
    pub cpu_score: u32,
    pub network_bps_column: u64,
    pub parameters_cbor: Vec<u8>,
    pub measured_at_ms: u64,
}

impl Store {
    pub fn record_local_capacity_measurement(
        &mut self,
        measurement: &NewLocalCapacityMeasurement,
    ) -> Result<(), AslError> {
        if measurement.direct_members > 1_000_000
            || measurement.gossip_members > MAX_MEMBER_COUNT
            || measurement.direct_members > measurement.gossip_members
            || measurement
                .memory_bytes
                .is_some_and(|value| value > MAX_RESOURCE_BYTES)
            || measurement.cpu_score > 1_000_000
            || measurement
                .network_bps
                .is_some_and(|value| value > MAX_RESOURCE_BYTES)
            || measurement.parameters_cbor.is_empty()
            || measurement.parameters_cbor.len() > MAX_PARAMETERS_BYTES
            || measurement.measured_at_ms > i64::MAX as u64
        {
            return Err(AslError::InvalidMessage);
        }

        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO local_capacity_measurements(
                    capacity_class,direct_members,gossip_members,memory_bytes,cpu_score,
                    network_bps,parameters_cbor,measured_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    measurement.capacity_class.as_str(),
                    i64::try_from(measurement.direct_members)
                        .map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(measurement.gossip_members)
                        .map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(measurement.memory_bytes.unwrap_or(0))
                        .map_err(|_| AslError::InvalidMessage)?,
                    i64::from(measurement.cpu_score),
                    i64::try_from(measurement.network_bps.unwrap_or(0))
                        .map_err(|_| AslError::InvalidMessage)?,
                    &measurement.parameters_cbor,
                    i64::try_from(measurement.measured_at_ms)
                        .map_err(|_| AslError::InvalidMessage)?,
                ],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM local_capacity_measurements
                 WHERE measurement_id NOT IN (
                    SELECT measurement_id FROM local_capacity_measurements
                    ORDER BY measured_at_ms DESC,measurement_id DESC LIMIT ?1
                 )",
                [MAX_CAPACITY_MEASUREMENTS],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    pub fn latest_local_capacity_measurement(
        &self,
    ) -> Result<Option<StoredLocalCapacityMeasurement>, AslError> {
        self.connection
            .query_row(
                "SELECT measurement_id,capacity_class,direct_members,gossip_members,
                        memory_bytes,cpu_score,network_bps,parameters_cbor,measured_at_ms
                 FROM local_capacity_measurements
                 ORDER BY measured_at_ms DESC,measurement_id DESC LIMIT 1",
                [],
                |row| {
                    let class: String = row.get(1)?;
                    let direct_members: i64 = row.get(2)?;
                    let gossip_members: i64 = row.get(3)?;
                    let memory_bytes_column: i64 = row.get(4)?;
                    let cpu_score: i64 = row.get(5)?;
                    let network_bps_column: i64 = row.get(6)?;
                    let measured_at_ms: i64 = row.get(8)?;
                    Ok((
                        row.get::<_, i64>(0)?,
                        class,
                        direct_members,
                        gossip_members,
                        memory_bytes_column,
                        cpu_score,
                        network_bps_column,
                        row.get::<_, Vec<u8>>(7)?,
                        measured_at_ms,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?
            .map(
                |(
                    measurement_id,
                    class,
                    direct_members,
                    gossip_members,
                    memory_bytes_column,
                    cpu_score,
                    network_bps_column,
                    parameters_cbor,
                    measured_at_ms,
                )| {
                    Ok(StoredLocalCapacityMeasurement {
                        measurement_id,
                        capacity_class: CapacityClass::parse(&class)?,
                        direct_members: nonnegative(direct_members)?,
                        gossip_members: nonnegative(gossip_members)?,
                        memory_bytes_column: nonnegative(memory_bytes_column)?,
                        cpu_score: u32::try_from(cpu_score)
                            .map_err(|_| AslError::InvalidDatabase)?,
                        network_bps_column: nonnegative(network_bps_column)?,
                        parameters_cbor,
                        measured_at_ms: nonnegative(measured_at_ms)?,
                    })
                },
            )
            .transpose()
    }
}

fn nonnegative(value: i64) -> Result<u64, AslError> {
    u64::try_from(value).map_err(|_| AslError::InvalidDatabase)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::open_store;

    #[test]
    fn latest_capacity_measurement_round_trips_and_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open_store(&directory.path().join("state.sqlite3")).unwrap();
        let measurement = NewLocalCapacityMeasurement {
            capacity_class: CapacityClass::Medium,
            direct_members: 128,
            gossip_members: 2048,
            memory_bytes: None,
            cpu_score: 42,
            network_bps: None,
            parameters_cbor: vec![0xa0],
            measured_at_ms: 100,
        };

        store
            .record_local_capacity_measurement(&measurement)
            .unwrap();
        let stored = store.latest_local_capacity_measurement().unwrap().unwrap();

        assert_eq!(stored.capacity_class, CapacityClass::Medium);
        assert_eq!(stored.direct_members, 128);
        assert_eq!(stored.gossip_members, 2048);
        assert_eq!(stored.memory_bytes_column, 0);
        assert_eq!(stored.cpu_score, 42);
        assert_eq!(stored.network_bps_column, 0);
        assert_eq!(stored.parameters_cbor, vec![0xa0]);
        assert_eq!(stored.measured_at_ms, 100);

        for measured_at_ms in 101..=165 {
            store
                .record_local_capacity_measurement(&NewLocalCapacityMeasurement {
                    capacity_class: CapacityClass::Medium,
                    direct_members: 128,
                    gossip_members: 2048,
                    memory_bytes: None,
                    cpu_score: 42,
                    network_bps: None,
                    parameters_cbor: vec![0xa0],
                    measured_at_ms,
                })
                .unwrap();
        }
        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM local_capacity_measurements",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, MAX_CAPACITY_MEASUREMENTS);
    }

    #[test]
    fn capacity_measurement_rejects_values_outside_schema_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open_store(&directory.path().join("state.sqlite3")).unwrap();
        let measurement = NewLocalCapacityMeasurement {
            capacity_class: CapacityClass::Small,
            direct_members: 0,
            gossip_members: 10_000_001,
            memory_bytes: None,
            cpu_score: 1_000_001,
            network_bps: None,
            parameters_cbor: vec![0xa0],
            measured_at_ms: 1,
        };

        assert!(
            store
                .record_local_capacity_measurement(&measurement)
                .is_err()
        );
    }
}
