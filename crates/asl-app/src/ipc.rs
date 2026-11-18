use std::env;
use std::io::{Read, Write};

use asl_types::{error::AslError, protocol::decode_control};

pub const MAX_IPC_FRAME_BYTES: usize = 4 * 1024 * 1024;
const HEADER_BYTES: usize = 20;
const TASK_BODY_HEADER_BYTES: usize = 21;
pub const MAX_IPC_TASK_PAYLOAD_BYTES: usize =
    MAX_IPC_FRAME_BYTES - HEADER_BYTES - TASK_BODY_HEADER_BYTES;
const MAGIC: [u8; 4] = *b"ASLI";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IpcRole {
    Core = 1,
    Net = 2,
    Worker = 3,
    Extractor = 4,
}

impl IpcRole {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::Core),
            2 => Ok(Self::Net),
            3 => Ok(Self::Worker),
            4 => Ok(Self::Extractor),
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn permits(self, receiver: Self, message: &IpcMessage) -> bool {
        matches!(
            (self, receiver, message),
            (
                Self::Core,
                Self::Net,
                IpcMessage::Shutdown | IpcMessage::Ping { .. }
            ) | (
                Self::Core,
                Self::Worker,
                IpcMessage::Shutdown
                    | IpcMessage::Ping { .. }
                    | IpcMessage::RunTask { .. }
                    | IpcMessage::TaskContinue { .. },
            ) | (
                Self::Core,
                Self::Extractor,
                IpcMessage::Shutdown | IpcMessage::Ping { .. }
            ) | (
                Self::Net | Self::Worker | Self::Extractor,
                Self::Core,
                IpcMessage::Ready | IpcMessage::Stopped | IpcMessage::Pong { .. },
            ) | (
                Self::Worker | Self::Extractor,
                Self::Core,
                IpcMessage::TaskResult { .. }
            ) | (Self::Worker, Self::Core, IpcMessage::TaskStarted { .. })
        )
    }

    pub(crate) fn startup_argument(self) -> Option<&'static str> {
        match self {
            Self::Core => None,
            Self::Net => Some("--asl-role=net"),
            Self::Worker => Some("--asl-role=worker"),
            Self::Extractor => Some("--asl-role=extractor"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WorkerOperation {
    ValidateControlFrame = 1,
}

impl WorkerOperation {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::ValidateControlFrame),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TaskStatus {
    Valid = 1,
    Invalid = 2,
}

impl TaskStatus {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::Valid),
            2 => Ok(Self::Invalid),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcMessage {
    Ready,
    Shutdown,
    Stopped,
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    RunTask {
        task_id: [u8; 16],
        operation: WorkerOperation,
        payload: Vec<u8>,
    },
    TaskResult {
        task_id: [u8; 16],
        status: TaskStatus,
    },
    TaskStarted {
        task_id: [u8; 16],
    },
    TaskContinue {
        task_id: [u8; 16],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcFrame {
    pub role: IpcRole,
    pub sequence: u64,
    pub message: IpcMessage,
}

pub fn encode_frame(
    sender: IpcRole,
    receiver: IpcRole,
    sequence: u64,
    message: &IpcMessage,
) -> Result<Vec<u8>, AslError> {
    if sequence == 0 || !sender.permits(receiver, message) {
        return Err(AslError::InvalidMessage);
    }

    let (kind, body) = encode_message(message)?;
    let total = HEADER_BYTES
        .checked_add(body.len())
        .filter(|length| *length <= MAX_IPC_FRAME_BYTES)
        .ok_or(AslError::InvalidMessage)?;
    let body_len = u32::try_from(body.len()).map_err(|_| AslError::InvalidMessage)?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&VERSION.to_be_bytes());
    frame.push(sender as u8);
    frame.push(kind);
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_frame(
    bytes: &[u8],
    expected_sender: IpcRole,
    receiver: IpcRole,
    expected_sequence: u64,
) -> Result<IpcFrame, AslError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_IPC_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    if bytes[..4] != MAGIC || u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION {
        return Err(AslError::InvalidMessage);
    }

    let role = IpcRole::from_wire(bytes[6])?;
    let sequence = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let payload_len = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let exact_len = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(AslError::InvalidMessage)?;
    if role != expected_sender
        || sequence != expected_sequence
        || sequence == 0
        || exact_len != bytes.len()
    {
        return Err(AslError::InvalidMessage);
    }

    let message = decode_message(bytes[7], &bytes[HEADER_BYTES..])?;
    if !role.permits(receiver, &message) {
        return Err(AslError::InvalidMessage);
    }
    Ok(IpcFrame {
        role,
        sequence,
        message,
    })
}

fn encode_message(message: &IpcMessage) -> Result<(u8, Vec<u8>), AslError> {
    let mut body = Vec::new();
    let kind = match message {
        IpcMessage::Ready => 1,
        IpcMessage::Shutdown => 2,
        IpcMessage::Stopped => 3,
        IpcMessage::Ping { nonce } => {
            body.extend_from_slice(&nonce.to_be_bytes());
            4
        }
        IpcMessage::Pong { nonce } => {
            body.extend_from_slice(&nonce.to_be_bytes());
            5
        }
        IpcMessage::RunTask {
            task_id,
            operation,
            payload,
        } => {
            if payload.len() > MAX_IPC_TASK_PAYLOAD_BYTES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(task_id);
            body.push(*operation as u8);
            body.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(payload);
            6
        }
        IpcMessage::TaskResult { task_id, status } => {
            body.extend_from_slice(task_id);
            body.push(*status as u8);
            7
        }
        IpcMessage::TaskStarted { task_id } => {
            body.extend_from_slice(task_id);
            8
        }
        IpcMessage::TaskContinue { task_id } => {
            body.extend_from_slice(task_id);
            9
        }
    };
    if HEADER_BYTES + body.len() > MAX_IPC_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    Ok((kind, body))
}

fn decode_message(kind: u8, body: &[u8]) -> Result<IpcMessage, AslError> {
    match kind {
        1 if body.is_empty() => Ok(IpcMessage::Ready),
        2 if body.is_empty() => Ok(IpcMessage::Shutdown),
        3 if body.is_empty() => Ok(IpcMessage::Stopped),
        4 if body.len() == 8 => Ok(IpcMessage::Ping {
            nonce: u64::from_be_bytes(body.try_into().unwrap()),
        }),
        5 if body.len() == 8 => Ok(IpcMessage::Pong {
            nonce: u64::from_be_bytes(body.try_into().unwrap()),
        }),
        6 if body.len() >= TASK_BODY_HEADER_BYTES => {
            let task_id = body[..16].try_into().unwrap();
            let operation = WorkerOperation::from_wire(body[16])?;
            let payload_len = u32::from_be_bytes(body[17..21].try_into().unwrap()) as usize;
            let expected_len = TASK_BODY_HEADER_BYTES
                .checked_add(payload_len)
                .ok_or(AslError::InvalidMessage)?;
            if body.len() != expected_len {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::RunTask {
                task_id,
                operation,
                payload: body[TASK_BODY_HEADER_BYTES..].to_vec(),
            })
        }
        7 if body.len() == 17 => Ok(IpcMessage::TaskResult {
            task_id: body[..16].try_into().unwrap(),
            status: TaskStatus::from_wire(body[16])?,
        }),
        8 if body.len() == 16 => Ok(IpcMessage::TaskStarted {
            task_id: body.try_into().unwrap(),
        }),
        9 if body.len() == 16 => Ok(IpcMessage::TaskContinue {
            task_id: body.try_into().unwrap(),
        }),
        _ => Err(AslError::InvalidMessage),
    }
}

pub struct FrameReader<R> {
    reader: R,
    expected_sender: IpcRole,
    receiver: IpcRole,
    next_sequence: Option<u64>,
}

impl<R: Read> FrameReader<R> {
    pub fn new(reader: R, expected_sender: IpcRole, receiver: IpcRole) -> Self {
        Self {
            reader,
            expected_sender,
            receiver,
            next_sequence: Some(1),
        }
    }

    pub fn receive(&mut self) -> Result<IpcFrame, AslError> {
        let sequence = self.next_sequence.ok_or(AslError::InvalidMessage)?;
        let mut header = [0u8; HEADER_BYTES];
        self.reader.read_exact(&mut header)?;
        let payload_len = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
        let total_len = HEADER_BYTES
            .checked_add(payload_len)
            .filter(|length| *length <= MAX_IPC_FRAME_BYTES)
            .ok_or(AslError::InvalidMessage)?;
        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(&header);
        bytes.resize(total_len, 0);
        self.reader.read_exact(&mut bytes[HEADER_BYTES..])?;
        let frame = decode_frame(&bytes, self.expected_sender, self.receiver, sequence)?;
        self.next_sequence = sequence.checked_add(1);
        Ok(frame)
    }
}

pub struct FrameWriter<W> {
    writer: W,
    sender: IpcRole,
    receiver: IpcRole,
    next_sequence: Option<u64>,
    failed: bool,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(writer: W, sender: IpcRole, receiver: IpcRole) -> Self {
        Self {
            writer,
            sender,
            receiver,
            next_sequence: Some(1),
            failed: false,
        }
    }

    pub fn send(&mut self, message: &IpcMessage) -> Result<(), AslError> {
        if self.failed {
            return Err(AslError::InvalidMessage);
        }
        let sequence = self.next_sequence.ok_or(AslError::InvalidMessage)?;
        let frame = encode_frame(self.sender, self.receiver, sequence, message)?;
        if let Err(error) = self
            .writer
            .write_all(&frame)
            .and_then(|()| self.writer.flush())
        {
            self.failed = true;
            return Err(error.into());
        }
        self.next_sequence = sequence.checked_add(1);
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

pub(crate) fn validate_control_payload(payload: &[u8]) -> TaskStatus {
    if decode_control(payload).is_ok() {
        TaskStatus::Valid
    } else {
        TaskStatus::Invalid
    }
}

pub fn run_net_child() -> Result<(), AslError> {
    run_child_for(&[IpcRole::Net])
}

pub fn run_worker_child() -> Result<(), AslError> {
    run_child_for(&[IpcRole::Worker, IpcRole::Extractor])
}

fn run_child_for(allowed_roles: &[IpcRole]) -> Result<(), AslError> {
    let mut arguments = env::args_os();
    let _executable = arguments.next();
    let argument = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(AslError::InvalidMessage)?;
    if arguments.next().is_some() {
        return Err(AslError::InvalidMessage);
    }
    let role = allowed_roles
        .iter()
        .copied()
        .find(|role| role.startup_argument() == Some(argument.as_str()))
        .ok_or(AslError::InvalidMessage)?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = FrameReader::new(stdin.lock(), IpcRole::Core, role);
    let mut writer = FrameWriter::new(stdout.lock(), role, IpcRole::Core);
    writer.send(&IpcMessage::Ready)?;
    loop {
        match reader.receive()?.message {
            IpcMessage::Shutdown => {
                writer.send(&IpcMessage::Stopped)?;
                return Ok(());
            }
            IpcMessage::Ping { nonce } => writer.send(&IpcMessage::Pong { nonce })?,
            IpcMessage::RunTask {
                task_id,
                operation: WorkerOperation::ValidateControlFrame,
                payload,
            } if role == IpcRole::Worker => {
                writer.send(&IpcMessage::TaskStarted { task_id })?;
                if reader.receive()?.message != (IpcMessage::TaskContinue { task_id }) {
                    return Err(AslError::InvalidMessage);
                }
                writer.send(&IpcMessage::TaskResult {
                    task_id,
                    status: validate_control_payload(&payload),
                })?;
            }
            _ => return Err(AslError::InvalidMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ready_frame(sender: IpcRole, sequence: u64) -> Vec<u8> {
        encode_frame(sender, IpcRole::Core, sequence, &IpcMessage::Ready).unwrap()
    }

    #[test]
    fn fixed_messages_round_trip_with_role_and_sequence_binding() {
        let messages = [
            IpcMessage::Ready,
            IpcMessage::Shutdown,
            IpcMessage::Stopped,
            IpcMessage::Ping { nonce: 42 },
            IpcMessage::Pong { nonce: 42 },
            IpcMessage::RunTask {
                task_id: [3; 16],
                operation: WorkerOperation::ValidateControlFrame,
                payload: vec![0x82, 0x01, 0x02],
            },
            IpcMessage::TaskResult {
                task_id: [3; 16],
                status: TaskStatus::Invalid,
            },
            IpcMessage::TaskStarted { task_id: [3; 16] },
            IpcMessage::TaskContinue { task_id: [3; 16] },
        ];
        for message in messages {
            let (sender, receiver) = match message {
                IpcMessage::Ready | IpcMessage::Stopped | IpcMessage::Pong { .. } => {
                    (IpcRole::Net, IpcRole::Core)
                }
                IpcMessage::Shutdown | IpcMessage::Ping { .. } => (IpcRole::Core, IpcRole::Net),
                IpcMessage::RunTask { .. } => (IpcRole::Core, IpcRole::Worker),
                IpcMessage::TaskResult { .. } | IpcMessage::TaskStarted { .. } => {
                    (IpcRole::Worker, IpcRole::Core)
                }
                IpcMessage::TaskContinue { .. } => (IpcRole::Core, IpcRole::Worker),
            };
            let bytes = encode_frame(sender, receiver, 7, &message).unwrap();
            let decoded = decode_frame(&bytes, sender, receiver, 7).unwrap();
            assert_eq!(decoded.message, message);
            assert_eq!(decoded.sequence, 7);
        }
    }

    #[test]
    fn rejects_unknown_role_kind_and_operation() {
        let mut bytes = ready_frame(IpcRole::Net, 1);
        bytes[6] = 99;
        assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1).is_err());

        let mut bytes = ready_frame(IpcRole::Net, 1);
        bytes[7] = 99;
        assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1).is_err());

        let mut bytes = encode_frame(
            IpcRole::Core,
            IpcRole::Worker,
            1,
            &IpcMessage::RunTask {
                task_id: [0; 16],
                operation: WorkerOperation::ValidateControlFrame,
                payload: Vec::new(),
            },
        )
        .unwrap();
        bytes[HEADER_BYTES + 16] = 99;
        assert!(decode_frame(&bytes, IpcRole::Core, IpcRole::Worker, 1).is_err());
    }

    #[test]
    fn rejects_wrong_direction_and_non_monotonic_sequences() {
        let bytes = encode_frame(IpcRole::Net, IpcRole::Core, 1, &IpcMessage::Ready).unwrap();
        assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 2).is_err());
        assert!(encode_frame(IpcRole::Worker, IpcRole::Core, 1, &IpcMessage::Ready,).is_ok());
        assert!(
            encode_frame(
                IpcRole::Core,
                IpcRole::Net,
                1,
                &IpcMessage::TaskResult {
                    task_id: [0; 16],
                    status: TaskStatus::Valid,
                },
            )
            .is_err()
        );

        let first = ready_frame(IpcRole::Net, 1);
        let mut input = first.clone();
        input.extend_from_slice(&first);
        let mut reader = FrameReader::new(Cursor::new(input), IpcRole::Net, IpcRole::Core);
        assert!(matches!(
            reader.receive().unwrap().message,
            IpcMessage::Ready
        ));
        assert!(reader.receive().is_err());
    }

    #[test]
    fn enforces_four_mib_total_frame_limit() {
        let max_payload = MAX_IPC_TASK_PAYLOAD_BYTES;
        let message = IpcMessage::RunTask {
            task_id: [1; 16],
            operation: WorkerOperation::ValidateControlFrame,
            payload: vec![0; max_payload],
        };
        assert_eq!(
            encode_frame(IpcRole::Core, IpcRole::Worker, 1, &message)
                .unwrap()
                .len(),
            MAX_IPC_FRAME_BYTES
        );

        let oversized = IpcMessage::RunTask {
            task_id: [1; 16],
            operation: WorkerOperation::ValidateControlFrame,
            payload: vec![0; max_payload + 1],
        };
        assert!(encode_frame(IpcRole::Core, IpcRole::Worker, 1, &oversized).is_err());
    }

    #[test]
    fn worker_result_contains_only_a_fixed_status() {
        assert_eq!(validate_control_payload(&[]), TaskStatus::Invalid);
        assert_eq!(validate_control_payload(&[0xff]), TaskStatus::Invalid);
    }
}
