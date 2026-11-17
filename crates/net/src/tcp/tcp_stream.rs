// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the TCP structures for demuxing TCP into streams of DNS packets.

use core::mem;
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;

use futures_io::IoSlice;
use futures_util::stream::Stream;
use futures_util::{self, future::Future, ready};
use tracing::{debug, trace};

use crate::proto::op::SerialMessage;
use crate::runtime::{DnsTcpStream, Time};
use crate::xfer::{BufDnsStreamHandle, StreamReceiver};

/// Current state while writing to the remote of the TCP connection
enum WriteTcpState {
    /// Currently writing the length of bytes to of the buffer.
    LenBytes {
        /// Current position in the length buffer being written
        pos: usize,
        /// Length of the buffer
        length: [u8; 2],
        /// Buffer to write after the length
        bytes: Vec<u8>,
    },
    /// Currently writing the buffer to the remote
    Bytes {
        /// Current position in the buffer written
        pos: usize,
        /// Buffer to write to the remote
        bytes: Vec<u8>,
    },
    /// Currently flushing the bytes to the remote
    Flushing,
}

/// Amount of memory reserved up front for a message being read, and the floor for each
/// subsequent growth step.
///
/// The two byte length prefix is chosen by the peer, so the message buffer is grown as data
/// actually arrives instead of being sized to the full length (up to 64 KiB) immediately.
const READ_ALLOC_STEP: usize = 1024;

/// Current state of a TCP stream as it's being read.
pub(crate) enum ReadTcpState {
    /// Currently reading the length of the TCP packet
    LenBytes {
        /// Current position in the buffer
        pos: usize,
        /// Buffer of the length to read
        bytes: [u8; 2],
    },
    /// Currently reading the bytes of the DNS packet
    Bytes {
        /// Current position while reading the buffer
        pos: usize,
        /// buffer being read into
        bytes: Vec<u8>,
        /// Total length of the message announced by the length prefix
        len: usize,
    },
}

/// A Stream used for sending data to and from a remote DNS endpoint (client or server).
#[must_use = "futures do nothing unless polled"]
pub struct TcpStream<S: DnsTcpStream> {
    socket: S,
    outbound_messages: StreamReceiver,
    send_state: Option<WriteTcpState>,
    read_state: ReadTcpState,
    peer_addr: SocketAddr,
}

impl<S: DnsTcpStream> TcpStream<S> {
    /// Returns the address of the peer connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn pollable_split(
        &mut self,
    ) -> (
        &mut S,
        &mut StreamReceiver,
        &mut Option<WriteTcpState>,
        &mut ReadTcpState,
    ) {
        (
            &mut self.socket,
            &mut self.outbound_messages,
            &mut self.send_state,
            &mut self.read_state,
        )
    }

    /// Initializes a TcpStream with an established connection.
    ///
    /// Uses the default buffer size (32) for the outbound message queue.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    /// * `peer_addr` - address of the remote peer
    pub fn from_stream(stream: S, peer_addr: SocketAddr) -> (Self, BufDnsStreamHandle) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);
        let stream = Self::from_stream_with_receiver(stream, peer_addr, outbound_messages);
        (stream, message_sender)
    }

    /// Initializes a TcpStream with an established connection and explicit buffer size.
    ///
    /// Use this when you need a larger buffer to handle high message rates without
    /// dropping messages due to backpressure.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    /// * `peer_addr` - address of the remote peer
    /// * `buffer_size` - maximum number of messages that can be queued for sending
    pub fn from_stream_with_buffer_size(
        stream: S,
        peer_addr: SocketAddr,
        buffer_size: usize,
    ) -> (Self, BufDnsStreamHandle) {
        let (message_sender, outbound_messages) =
            BufDnsStreamHandle::with_buffer_size(peer_addr, buffer_size);
        let stream = Self::from_stream_with_receiver(stream, peer_addr, outbound_messages);
        (stream, message_sender)
    }

    /// Wraps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver(
        socket: S,
        peer_addr: SocketAddr,
        outbound_messages: StreamReceiver,
    ) -> Self {
        Self {
            socket,
            outbound_messages,
            send_state: None,
            read_state: ReadTcpState::LenBytes {
                pos: 0,
                bytes: [0u8; 2],
            },
            peer_addr,
        }
    }

    /// Creates a new future of the eventually establish a IO stream connection or fail trying
    ///
    /// # Arguments
    ///
    /// * `future` - underlying stream future which this tcp stream relies on
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    pub fn with_future<F: Future<Output = Result<S, io::Error>> + Send + 'static>(
        future: F,
        name_server: SocketAddr,
        timeout: Duration,
    ) -> (
        impl Future<Output = Result<Self, io::Error>> + Send,
        BufDnsStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);
        let stream_fut = Self::connect_with_future(future, name_server, timeout, outbound_messages);

        (stream_fut, message_sender)
    }

    async fn connect_with_future<F: Future<Output = Result<S, io::Error>> + Send + 'static>(
        future: F,
        name_server: SocketAddr,
        timeout: Duration,
        outbound_messages: StreamReceiver,
    ) -> Result<Self, io::Error> {
        let socket = S::Time::timeout(timeout, future).await??;
        debug!("TCP connection established to: {}", name_server);
        Ok(Self {
            socket,
            outbound_messages,
            send_state: None,
            read_state: ReadTcpState::LenBytes {
                pos: 0,
                bytes: [0u8; 2],
            },
            peer_addr: name_server,
        })
    }
}

impl<S: DnsTcpStream> Stream for TcpStream<S> {
    type Item = io::Result<SerialMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let peer = self.peer_addr;
        let (socket, outbound_messages, send_state, read_state) = self.pollable_split();
        let mut socket = Pin::new(socket);
        let mut outbound_messages = Pin::new(outbound_messages);

        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        // TODO: it might be interesting to try and split the sending and receiving futures.
        loop {
            // in the case we are sending, send it all?
            if send_state.is_some() {
                // sending...
                match send_state {
                    Some(WriteTcpState::LenBytes { pos, length, bytes }) => {
                        let wrote = ready!(socket.as_mut().poll_write_vectored(
                            cx,
                            &[IoSlice::new(&length[*pos..]), IoSlice::new(bytes)]
                        ))?;
                        *pos += wrote;
                    }
                    Some(WriteTcpState::Bytes { pos, bytes }) => {
                        let wrote = ready!(socket.as_mut().poll_write(cx, &bytes[*pos..]))?;
                        *pos += wrote;
                    }
                    Some(WriteTcpState::Flushing) => {
                        ready!(socket.as_mut().poll_flush(cx))?;
                    }
                    _ => (),
                }

                // get current state
                let current_state = send_state.take();

                // switch states
                match current_state {
                    Some(WriteTcpState::LenBytes { pos, length, bytes }) => {
                        if pos < length.len() {
                            *send_state = Some(WriteTcpState::LenBytes { pos, length, bytes });
                        } else if pos < length.len() + bytes.len() {
                            *send_state = Some(WriteTcpState::Bytes {
                                pos: pos - length.len(),
                                bytes,
                            });
                        } else {
                            *send_state = Some(WriteTcpState::Flushing);
                        }
                    }
                    Some(WriteTcpState::Bytes { pos, bytes }) => {
                        if pos < bytes.len() {
                            *send_state = Some(WriteTcpState::Bytes { pos, bytes });
                        } else {
                            // At this point we successfully delivered the entire message.
                            //  flush
                            *send_state = Some(WriteTcpState::Flushing);
                        }
                    }
                    Some(WriteTcpState::Flushing) => {
                        // At this point we successfully delivered the entire message.
                        send_state.take();
                    }
                    None => (),
                };
            } else {
                // then see if there is more to send
                match outbound_messages.as_mut().poll_next(cx)
                    // .map_err(|()| io::Error::new(io::ErrorKind::Other, "unknown"))?
                {
                    // already handled above, here to make sure the poll() pops the next message
                    Poll::Ready(Some(message)) => {
                        // if there is no peer, this connection should die...
                        let (buffer, dst) = message.into();

                        // This is an error if the destination is not our peer (this is TCP after all)
                        //  This will kill the connection...
                        if peer != dst {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("mismatched peer: {peer} and dst: {dst}"),
                            ))));
                        }

                        // will return if the socket will block
                        // the length is 16 bits
                        let Ok(len) = u16::try_from(buffer.len()) else {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "message of {} bytes does not fit the 16-bit TCP length prefix",
                                    buffer.len()
                                ),
                            ))));
                        };
                        let len = len.to_be_bytes();

                        debug!("sending message len: {} to: {}", buffer.len(), dst);
                        *send_state = Some(WriteTcpState::LenBytes {
                            pos: 0,
                            length: len,
                            bytes: buffer,
                        });
                    }
                    // now we get to drop through to the receives...
                    // TODO: should we also return None if there are no more messages to send?
                    Poll::Pending => break,
                    Poll::Ready(None) => {
                        debug!("no messages to send");
                        break;
                    }
                }
            }
        }

        let mut ret_buf = None;

        // this will loop while there is data to read, or the data has been read, or an IO
        //  event would block
        while ret_buf.is_none() {
            // Evaluates the next state. If None is the result, then no state change occurs,
            //  if Some(_) is returned, then that will be used as the next state.
            let new_state: Option<ReadTcpState> = match read_state {
                ReadTcpState::LenBytes { pos, bytes } => {
                    // debug!("reading length {}", bytes.len());
                    let read = ready!(socket.as_mut().poll_read(cx, &mut bytes[*pos..]))?;
                    if read == 0 {
                        // the Stream was closed!
                        debug!("zero bytes read, stream closed?");
                        //try!(self.socket.shutdown(Shutdown::Both)); // TODO: add generic shutdown function

                        if *pos == 0 {
                            // Since this is the start of the next message, we have a clean end
                            return Poll::Ready(None);
                        } else {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "closed while reading length",
                            ))));
                        }
                    }
                    trace!("in ReadTcpState::LenBytes: {}", pos);
                    *pos += read;

                    if *pos < bytes.len() {
                        trace!("remain ReadTcpState::LenBytes: {}", pos);
                        None
                    } else {
                        let length = u16::from_be_bytes(*bytes);
                        trace!("got length: {}", length);
                        // The length prefix is attacker controlled, so only reserve enough to
                        // make progress and grow the buffer as bytes actually arrive. The rest
                        // of the message is allocated in the `ReadTcpState::Bytes` arm below.
                        let len = usize::from(length);
                        let capacity = Ord::min(len, READ_ALLOC_STEP);
                        let bytes = vec![0; capacity];

                        trace!("move ReadTcpState::Bytes: {}", len);
                        Some(ReadTcpState::Bytes { pos: 0, bytes, len })
                    }
                }
                ReadTcpState::Bytes { pos, bytes, len } => {
                    // Grow geometrically, and only once everything received so far has been
                    // consumed, so a peer that announces a large message but sends little (or
                    // nothing) never causes the full message to be allocated. `bytes` never
                    // grows past `len`, so the slice handed to `poll_read` cannot read past
                    // the end of the announced message.
                    if *pos == bytes.len() && bytes.len() < *len {
                        let grown =
                            Ord::min(*len, bytes.len().saturating_mul(2).max(READ_ALLOC_STEP));
                        bytes.resize(grown, 0);
                    }

                    let read = ready!(socket.as_mut().poll_read(cx, &mut bytes[*pos..]))?;
                    if read == 0 {
                        // the Stream was closed!
                        trace!("zero bytes read for message, stream closed?");

                        // Since this is the start of the next message, we have a clean end
                        // try!(self.socket.shutdown(Shutdown::Both));  // TODO: add generic shutdown function
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "closed while reading message",
                        ))));
                    }

                    trace!("in ReadTcpState::Bytes: {}", bytes.len());
                    *pos += read;

                    if *pos < *len {
                        trace!("remain ReadTcpState::Bytes: {}", *len);
                        None
                    } else {
                        trace!("reset ReadTcpState::LenBytes: {}", 0);
                        Some(ReadTcpState::LenBytes {
                            pos: 0,
                            bytes: [0u8; 2],
                        })
                    }
                }
            };

            // this will move to the next state,
            //  if it was a completed receipt of bytes, then it will move out the bytes
            if let Some(state) = new_state {
                if let ReadTcpState::Bytes { pos, bytes, len } = mem::replace(read_state, state) {
                    // The message is only handed off once all announced bytes arrived; the
                    // buffer is grown to exactly `len` by then, never beyond it.
                    assert_eq!(pos, len);
                    ret_buf = Some(bytes);
                }
            }
        }

        // if the buffer is ready, return it, if not we're Pending
        if let Some(buffer) = ret_buf {
            let src_addr = self.peer_addr;
            Poll::Ready(Some(Ok(SerialMessage::new(buffer, src_addr))))
        } else {
            debug!("bottomed out");
            // at a minimum the outbound_messages should have been polled,
            //  which will wake this future up later...
            Poll::Pending
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use core::time::Duration;
    use std::io;
    use std::io::Write as _;

    use futures_util::StreamExt;
    use test_support::subscribe;

    use super::TcpStream;
    use crate::proto::op::SerialMessage;
    use crate::runtime::{RuntimeProvider, TokioRuntimeProvider};
    use crate::tcp::tests::tcp_stream_test;
    use crate::xfer::dns_handle::DnsStreamHandle;

    #[tokio::test]
    async fn test_tcp_stream_ipv4() {
        subscribe();
        tcp_stream_test(IpAddr::V4(Ipv4Addr::LOCALHOST), TokioRuntimeProvider::new()).await;
    }

    #[tokio::test]
    async fn test_tcp_stream_ipv6() {
        subscribe();
        tcp_stream_test(IpAddr::V6(Ipv6Addr::LOCALHOST), TokioRuntimeProvider::new()).await;
    }

    #[tokio::test]
    async fn test_tcp_stream_rejects_oversized_message() {
        subscribe();
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = listener.local_addr().unwrap();

        let tcp = TokioRuntimeProvider::new()
            .connect_tcp(server_addr, None, None)
            .await
            .unwrap();
        let (_server, _) = listener.accept().unwrap();
        let (mut stream, mut sender) = TcpStream::from_stream(tcp, server_addr);

        // 65536 bytes would wrap to a length prefix of 0
        let oversized = vec![0; usize::from(u16::MAX) + 1];
        sender
            .send(SerialMessage::new(oversized, server_addr))
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("oversized message was written instead of rejected");
        let Some(Err(error)) = result else {
            panic!("expected an error for the oversized message");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// Spawns a one-shot raw TCP server on loopback that writes `wire` to the first accepted
    /// connection and then holds that connection open until the returned sender is dropped.
    ///
    /// This bypasses the writer side of [`TcpStream`] so the read side can be fed a hand
    /// crafted length prefix and payload.
    fn spawn_raw_server(
        wire: Vec<u8>,
    ) -> (
        SocketAddr,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = listener.local_addr().unwrap();
        let (release, released) = std::sync::mpsc::channel();

        let handle = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.write_all(&wire).unwrap();
            socket.flush().unwrap();
            // Keep the connection open while the client is observed in a partial read state.
            let _ = released.recv_timeout(Duration::from_secs(5));
        });

        (server_addr, release, handle)
    }

    /// A full 64 KiB message must still be read end to end now that the buffer grows from
    /// 1 KiB as data arrives instead of being allocated up front.
    #[tokio::test]
    async fn test_tcp_stream_reads_max_length_message() {
        subscribe();
        let payload = vec![0xABu8; usize::from(u16::MAX)];
        let mut wire = Vec::with_capacity(payload.len() + 2);
        wire.extend_from_slice(&u16::MAX.to_be_bytes());
        wire.extend_from_slice(&payload);

        let (server_addr, release, server) = spawn_raw_server(wire);

        let tcp = TokioRuntimeProvider::new()
            .connect_tcp(server_addr, None, None)
            .await
            .unwrap();
        let (mut stream, _sender) = TcpStream::from_stream(tcp, server_addr);

        let message = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out reading the 64 KiB message")
            .expect("stream ended before the message was complete")
            .expect("error reading the 64 KiB message");

        assert_eq!(message.bytes(), payload.as_slice());

        drop(release);
        server.join().unwrap();
    }

    /// A message that needs more than one growth step is read in full and returned without
    /// the trailing slack that the intermediate buffers carry.
    #[tokio::test]
    async fn test_tcp_stream_reads_grown_message() {
        subscribe();
        let payload = vec![0x5Au8; 10_000];
        let length = u16::try_from(payload.len()).unwrap();
        let mut wire = Vec::with_capacity(payload.len() + 2);
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(&payload);

        let (server_addr, release, server) = spawn_raw_server(wire);

        let tcp = TokioRuntimeProvider::new()
            .connect_tcp(server_addr, None, None)
            .await
            .unwrap();
        let (mut stream, _sender) = TcpStream::from_stream(tcp, server_addr);

        let message = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out reading the 10 KB message")
            .expect("stream ended before the message was complete")
            .expect("error reading the 10 KB message");

        assert_eq!(message.bytes(), payload.as_slice());

        drop(release);
        server.join().unwrap();
    }

    /// A peer that announces a full sized message but only sends a few bytes must leave the
    /// reader pending: no panic and no error. The remaining bytes are the upper layer's
    /// problem (i.e. its timeout), exactly as before.
    #[tokio::test]
    async fn test_tcp_stream_waits_for_incomplete_message() {
        subscribe();
        let mut wire = Vec::with_capacity(18);
        wire.extend_from_slice(&u16::MAX.to_be_bytes());
        wire.extend_from_slice(&[0xCDu8; 16]);

        let (server_addr, release, server) = spawn_raw_server(wire);

        let tcp = TokioRuntimeProvider::new()
            .connect_tcp(server_addr, None, None)
            .await
            .unwrap();
        let (mut stream, _sender) = TcpStream::from_stream(tcp, server_addr);

        let result = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
        assert!(
            result.is_err(),
            "an incomplete message must not produce a message or an error"
        );

        drop(release);
        server.join().unwrap();
    }
}
