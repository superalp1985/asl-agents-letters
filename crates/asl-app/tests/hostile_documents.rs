use asl_app::ipc::{
    ExtractorOperation, ExtractorStatus, IpcMessage, IpcRole, MAX_IPC_EXTRACTOR_INPUT_BYTES,
    MAX_IPC_EXTRACTOR_OUTPUT_BYTES, decode_frame, encode_frame,
};

#[test]
fn extractor_messages_round_trip_only_between_core_and_extractor() {
    let request = IpcMessage::RunExtractorTask {
        task_id: [4; 16],
        operation: ExtractorOperation::PdfText,
        payload: b"%PDF-1.7".to_vec(),
    };
    let frame = encode_frame(IpcRole::Core, IpcRole::Extractor, 1, &request).unwrap();
    assert_eq!(
        decode_frame(&frame, IpcRole::Core, IpcRole::Extractor, 1)
            .unwrap()
            .message,
        request
    );

    let response = IpcMessage::ExtractorResult {
        task_id: [4; 16],
        status: ExtractorStatus::Completed,
        payload: b"extracted data".to_vec(),
    };
    let frame = encode_frame(IpcRole::Extractor, IpcRole::Core, 1, &response).unwrap();
    assert_eq!(
        decode_frame(&frame, IpcRole::Extractor, IpcRole::Core, 1)
            .unwrap()
            .message,
        response
    );
    assert!(encode_frame(IpcRole::Worker, IpcRole::Core, 1, &response).is_err());
    assert!(encode_frame(IpcRole::Core, IpcRole::Worker, 1, &request).is_err());
}

#[test]
fn extractor_input_and_output_limits_are_enforced_by_the_frame_codec() {
    assert!(
        encode_frame(
            IpcRole::Core,
            IpcRole::Extractor,
            1,
            &IpcMessage::RunExtractorTask {
                task_id: [5; 16],
                operation: ExtractorOperation::Avatar,
                payload: vec![0; MAX_IPC_EXTRACTOR_INPUT_BYTES + 1],
            },
        )
        .is_err()
    );
    assert!(
        encode_frame(
            IpcRole::Extractor,
            IpcRole::Core,
            1,
            &IpcMessage::ExtractorResult {
                task_id: [5; 16],
                status: ExtractorStatus::Completed,
                payload: vec![0; MAX_IPC_EXTRACTOR_OUTPUT_BYTES + 1],
            },
        )
        .is_err()
    );
    assert!(
        encode_frame(
            IpcRole::Extractor,
            IpcRole::Core,
            1,
            &IpcMessage::ExtractorResult {
                task_id: [5; 16],
                status: ExtractorStatus::Rejected,
                payload: vec![1],
            },
        )
        .is_err()
    );
}

#[test]
fn extractor_operation_and_result_status_are_fixed_enumerations() {
    let mut request = encode_frame(
        IpcRole::Core,
        IpcRole::Extractor,
        1,
        &IpcMessage::RunExtractorTask {
            task_id: [6; 16],
            operation: ExtractorOperation::PdfText,
            payload: Vec::new(),
        },
    )
    .unwrap();
    request[36] = 255;
    assert!(decode_frame(&request, IpcRole::Core, IpcRole::Extractor, 1).is_err());

    let mut response = encode_frame(
        IpcRole::Extractor,
        IpcRole::Core,
        1,
        &IpcMessage::ExtractorResult {
            task_id: [6; 16],
            status: ExtractorStatus::Rejected,
            payload: Vec::new(),
        },
    )
    .unwrap();
    response[36] = 255;
    assert!(decode_frame(&response, IpcRole::Extractor, IpcRole::Core, 1).is_err());
}
