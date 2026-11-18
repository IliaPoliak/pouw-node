//! The frames of the request-response protocols (`status` and `sync`): every request and
//! every answer is one frame, a `u32` big-endian length and that many bytes. The length is
//! checked against the limit of the protocol before a byte of the body is read, so a peer
//! that announces a huge frame costs the node nothing but the connection.
//!
//! The bytes inside a frame are the messages of [`protocol`](super::protocol); this module
//! knows only their size.

use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};

/// The codec of one request-response protocol, with the most bytes a request and an
/// answer of it may have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameCodec {
    pub max_request: usize,
    pub max_response: usize,
}

impl request_response::Codec for FrameCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, self.max_request).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, self.max_response).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &request, self.max_request).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &response, self.max_response).await
    }
}

/// Reads one frame of at most `max` bytes. A length above `max` is refused before the
/// body is read, and the body is read as it arrives, so the buffer never holds more than
/// the peer has sent.
pub async fn read_frame<T>(io: &mut T, max: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 4];
    io.read_exact(&mut prefix).await?;
    let announced = u32::from_be_bytes(prefix);
    let len = usize::try_from(announced)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a frame of {len} bytes, the limit is {max}"),
        ));
    }
    let mut bytes = Vec::new();
    let read = io
        .take(u64::from(announced))
        .read_to_end(&mut bytes)
        .await?;
    if read != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("a frame of {len} bytes ended after {read}"),
        ));
    }
    Ok(bytes)
}

/// Writes `bytes` as one frame. More than `max` bytes is an error and nothing is written.
pub async fn write_frame<T>(io: &mut T, bytes: &[u8], max: usize) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    if bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a frame of {} bytes, the limit is {max}", bytes.len()),
        ));
    }
    let len = u32::try_from(bytes.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(bytes).await?;
    io.flush().await
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use futures::io::Cursor;

    use super::*;

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn framed(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        block_on(write_frame(&mut out, bytes, 1 << 20)).unwrap();
        out
    }

    #[test]
    fn a_frame_is_its_length_and_its_bytes() {
        assert_eq!(framed(b"abc"), [0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(framed(b""), [0, 0, 0, 0]);
        let mut read = Cursor::new(framed(b"abc"));
        assert_eq!(block_on(read_frame(&mut read, 3)).unwrap(), b"abc");
        let mut empty = Cursor::new(framed(b""));
        assert_eq!(block_on(read_frame(&mut empty, 0)).unwrap(), b"");
    }

    #[test]
    fn a_length_over_the_limit_is_refused_before_the_body_is_read() {
        // the length says four gigabytes, no body follows
        let mut read = Cursor::new(vec![0xff, 0xff, 0xff, 0xff]);
        let error = block_on(read_frame(&mut read, 1024)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let mut read = Cursor::new(framed(b"abcd"));
        let error = block_on(read_frame(&mut read, 3)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_frame_that_ends_early_is_an_error() {
        let mut short = framed(b"abcd");
        short.truncate(6);
        let error = block_on(read_frame(&mut Cursor::new(short), 10)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let error = block_on(read_frame(&mut Cursor::new(vec![0, 0]), 10)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_frame_over_the_limit_is_not_written() {
        let mut out = Vec::new();
        let error = block_on(write_frame(&mut out, b"abcd", 3)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(out, Vec::<u8>::new());
    }
}
