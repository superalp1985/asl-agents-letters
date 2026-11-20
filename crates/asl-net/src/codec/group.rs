use std::io;

use asl_types::protocol::{
    GroupEnvelope, MAX_EXTENDED_FRAME_BYTES, WireFrame, decode_frame, encode_frame,
};
use libp2p::{
    StreamProtocol,
    futures::io::{AsyncRead, AsyncWrite},
    request_response::Codec,
};

use super::{check_protocol, read_payload, write_payload};

pub const GROUP_PROTOCOL: StreamProtocol = StreamProtocol::new("/asl/group/1.0.0");

/// Frames only. Net never processes the enclosed MLS object.
#[derive(Clone, Copy, Debug, Default)]
pub struct GroupCodec;

impl Codec for GroupCodec {
    type Protocol = StreamProtocol;
    type Request = GroupEnvelope;
    type Response = GroupEnvelope;

    async fn read_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<GroupEnvelope>
    where
        T: AsyncRead + Unpin + Send,
    {
        check_protocol(protocol, GROUP_PROTOCOL)?;
        let payload = read_payload(io, MAX_EXTENDED_FRAME_BYTES).await?;
        match decode_frame(&payload) {
            Ok(WireFrame::GroupEnvelope(envelope)) => Ok(envelope),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }

    async fn read_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<GroupEnvelope>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_request(protocol, io).await
    }

    async fn write_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        envelope: GroupEnvelope,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        check_protocol(protocol, GROUP_PROTOCOL)?;
        let bytes = encode_frame(&WireFrame::GroupEnvelope(envelope))
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        write_payload(io, &bytes).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        envelope: GroupEnvelope,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_request(protocol, io, envelope).await
    }
}
