use std::{
    future::{Future, poll_fn},
    io,
    task::Poll,
    time::{Duration, Instant},
};

use asl_types::protocol::{
    GroupEnvelope, MAX_EXTENDED_FRAME_BYTES, WireFrame, decode_frame, encode_frame,
};
use libp2p::{
    StreamProtocol,
    futures::io::{AsyncRead, AsyncWrite, AsyncWriteExt},
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

/// Timing metadata is local to Net. Only `envelope` is encoded.
#[derive(Debug)]
pub(crate) struct TimedGroupEnvelope {
    pub(crate) envelope: GroupEnvelope,
    pub(crate) deadline: Instant,
}

pub(crate) struct GroupStreamCodec {
    timeout: Duration,
    inbound_deadline: Instant,
    outbound_deadline: Option<Instant>,
}

impl GroupStreamCodec {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            inbound_deadline: Instant::now() + timeout,
            outbound_deadline: None,
        }
    }
}

impl Clone for GroupStreamCodec {
    fn clone(&self) -> Self {
        // The pinned libp2p handler clones the codec immediately before
        // starting its per-substream timer, not when the read is first polled.
        Self::new(self.timeout)
    }
}

impl Codec for GroupStreamCodec {
    type Protocol = StreamProtocol;
    type Request = TimedGroupEnvelope;
    type Response = GroupEnvelope;

    async fn read_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let deadline = self.inbound_deadline;
        let envelope = before(deadline, GroupCodec.read_request(protocol, io)).await?;
        Ok(TimedGroupEnvelope { envelope, deadline })
    }

    async fn read_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let deadline = self.outbound_deadline.ok_or(io::ErrorKind::InvalidInput)?;
        before(deadline, GroupCodec.read_response(protocol, io)).await
    }

    async fn write_request<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.outbound_deadline = Some(request.deadline);
        write_and_close(request.deadline, protocol, io, request.envelope).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &StreamProtocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_and_close(self.inbound_deadline, protocol, io, response).await
    }
}

async fn write_and_close<T: AsyncWrite + Unpin + Send>(
    deadline: Instant,
    protocol: &StreamProtocol,
    io: &mut T,
    envelope: GroupEnvelope,
) -> io::Result<()> {
    before(deadline, GroupCodec.write_request(protocol, io, envelope)).await?;
    // The receiver requires EOF. Close within the budget rather than
    // leaving that step to libp2p's later (idempotent) close.
    before(deadline, io.close()).await
}

async fn before<T>(deadline: Instant, io: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::pin!(io);
    tokio::time::timeout_at(
        deadline.into(),
        poll_fn(|cx| {
            // Tokio's timeout polls its inner future first.
            if Instant::now() >= deadline {
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
            io.as_mut().poll(cx)
        }),
    )
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

#[cfg(test)]
mod tests {
    use std::{pin::Pin, task::Context};

    use asl_types::{ids::Id128, protocol::GroupOperation};

    use super::*;

    fn envelope() -> GroupEnvelope {
        GroupEnvelope {
            message_id: Id128([1; 16]),
            group_id: [2; 32].into(),
            epoch: 1,
            operation: GroupOperation::Application,
            ciphertext: vec![3; 16],
        }
    }

    #[tokio::test]
    async fn inbound_read_does_not_start_a_new_window_after_negotiation() {
        let mut frame = Vec::new();
        GroupCodec
            .write_request(&GROUP_PROTOCOL, &mut frame, envelope())
            .await
            .unwrap();
        let mut reader = frame.as_slice();
        let mut codec = GroupStreamCodec::new(Duration::from_millis(20)).clone();
        tokio::time::sleep_until(codec.inbound_deadline.into()).await;
        let error = codec
            .read_request(&GROUP_PROTOCOL, &mut reader)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(reader.len(), frame.len());
    }

    struct ClosePending(bool);

    impl AsyncWrite for ClosePending {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0 = true;
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn request_deadline_includes_closing_the_frame() {
        let mut stream = ClosePending(false);
        let mut codec = GroupStreamCodec::new(Duration::from_secs(1)).clone();
        let request = TimedGroupEnvelope {
            envelope: envelope(),
            deadline: Instant::now() + Duration::from_millis(250),
        };
        let error = codec
            .write_request(&GROUP_PROTOCOL, &mut stream, request)
            .await
            .unwrap_err();
        assert!(stream.0, "expected the writer to reach the blocked close");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
