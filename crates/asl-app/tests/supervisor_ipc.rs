use std::io::Cursor;

use asl_app::ipc::{
    FrameReader, FrameWriter, IpcMessage, IpcRole, MAX_IPC_FRAME_BYTES, MAX_IPC_TASK_PAYLOAD_BYTES,
    TaskStatus, WorkerOperation, decode_frame, encode_frame,
};

#[test]
fn bounded_stream_preserves_sequence_and_structured_task_results() {
    let mut writer = FrameWriter::new(Vec::new(), IpcRole::Worker, IpcRole::Core);
    writer
        .send(&IpcMessage::Ready)
        .expect("encode first worker frame");
    writer
        .send(&IpcMessage::TaskStarted { task_id: [5; 16] })
        .expect("encode worker task start");
    writer
        .send(&IpcMessage::TaskResult {
            task_id: [5; 16],
            status: TaskStatus::Invalid,
        })
        .expect("encode worker task result");
    let bytes = writer.into_inner();
    let mut reader = FrameReader::new(Cursor::new(bytes), IpcRole::Worker, IpcRole::Core);
    assert_eq!(reader.receive().unwrap().message, IpcMessage::Ready);
    assert_eq!(
        reader.receive().unwrap().message,
        IpcMessage::TaskStarted { task_id: [5; 16] }
    );
    assert_eq!(
        reader.receive().unwrap().message,
        IpcMessage::TaskResult {
            task_id: [5; 16],
            status: TaskStatus::Invalid,
        }
    );
}

#[test]
fn unknown_roles_operations_and_oversized_frames_are_rejected() {
    let mut unknown_role =
        encode_frame(IpcRole::Net, IpcRole::Core, 1, &IpcMessage::Ready).unwrap();
    unknown_role[6] = 99;
    assert!(decode_frame(&unknown_role, IpcRole::Net, IpcRole::Core, 1).is_err());

    let mut unknown_operation = encode_frame(
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
    unknown_operation[36] = 99;
    assert!(decode_frame(&unknown_operation, IpcRole::Core, IpcRole::Worker, 1).is_err());

    let mut oversized = encode_frame(IpcRole::Net, IpcRole::Core, 1, &IpcMessage::Ready).unwrap();
    oversized[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(oversized.len() < MAX_IPC_FRAME_BYTES);
    assert!(decode_frame(&oversized, IpcRole::Net, IpcRole::Core, 1).is_err());
    assert!(
        FrameReader::new(Cursor::new(oversized), IpcRole::Net, IpcRole::Core)
            .receive()
            .is_err()
    );

    assert!(
        encode_frame(
            IpcRole::Core,
            IpcRole::Worker,
            1,
            &IpcMessage::RunTask {
                task_id: [0; 16],
                operation: WorkerOperation::ValidateControlFrame,
                payload: vec![0; MAX_IPC_TASK_PAYLOAD_BYTES + 1],
            },
        )
        .is_err()
    );
}
