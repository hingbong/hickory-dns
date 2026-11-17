// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `Server` component for hosting domain name server operations.

#[cfg(any(
    feature = "__tls",
    feature = "__quic",
    feature = "__https",
    feature = "__h3"
))]
use std::future::Future;
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use futures_util::StreamExt;
use hickory_proto::{
    op::{DEFAULT_MAX_PAYLOAD_LEN, Edns},
    rr::rdata::opt::NSIDPayload,
};
use ipnet::IpNet;
#[cfg(feature = "__tls")]
use rustls::{ServerConfig, server::ResolvesServerCert};
#[cfg(any(
    feature = "__tls",
    feature = "__quic",
    feature = "__https",
    feature = "__h3"
))]
use tokio::time::{error::Elapsed, timeout};
use tokio::{
    net,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
#[cfg(feature = "__tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

#[cfg(feature = "metrics")]
use crate::metrics::{AdmissionMetrics, ResponseHandlerMetrics};
#[cfg(feature = "__h3")]
use crate::net::h3::h3_server::H3Server;
#[cfg(feature = "__quic")]
use crate::net::quic::QuicServer;
#[cfg(feature = "__tls")]
use crate::net::tls::{default_provider, tls_from_stream};
use crate::{
    access::AccessControl,
    net::{
        BufDnsStreamHandle, DnsStreamHandle, NetError,
        runtime::{TokioTime, iocompat::AsyncIoTokioAsStd},
        tcp::TcpStream,
        udp::UdpStream,
        xfer::Protocol,
    },
    proto::{
        op::{
            Header, LowerQuery, MessageRequest, MessageType, Metadata, OpCode, Queries,
            ResponseCode, SerialMessage,
        },
        serialize::binary::{BinDecodable, BinDecoder},
    },
    zone_handler::MessageResponseBuilder,
};

#[cfg(feature = "__https")]
mod h2_handler;
#[cfg(feature = "__h3")]
mod h3_handler;
#[cfg(feature = "__quic")]
mod quic_handler;
mod request_handler;
pub use request_handler::{Request, RequestHandler, ResponseInfo};
mod timeout_stream;
pub use timeout_stream::TimeoutStream;

// TODO, would be nice to have a Slab for buffers here...
/// A Futures based implementation of a DNS server
pub struct Server<T: RequestHandler> {
    context: Arc<ServerContext<T>>,
    join_set: JoinSet<Result<(), NetError>>,
}

impl<T: RequestHandler> Server<T> {
    /// Creates a new ServerFuture with the specified Handler.
    pub fn new(handler: T) -> Self {
        Self::with_access(handler, [], [], DEFAULT_MAX_PAYLOAD_LEN, None)
    }

    /// Creates a new ServerFuture with the specified Handler and denied/allowed networks
    pub fn with_access(
        handler: T,
        denied_networks: impl IntoIterator<Item = IpNet>,
        allowed_networks: impl IntoIterator<Item = IpNet>,
        max_payload_size: u16,
        nsid: Option<NSIDPayload>,
    ) -> Self {
        Self::with_access_and_admission(
            handler,
            denied_networks,
            allowed_networks,
            max_payload_size,
            nsid,
            AdmissionConfig::default(),
        )
    }

    /// Creates a new ServerFuture with the specified Handler, denied/allowed networks, and
    /// inbound admission control settings.
    ///
    /// Using the default [`AdmissionConfig`] is equivalent to calling
    /// [`Server::with_access`].
    pub fn with_access_and_admission(
        handler: T,
        denied_networks: impl IntoIterator<Item = IpNet>,
        allowed_networks: impl IntoIterator<Item = IpNet>,
        max_payload_size: u16,
        nsid: Option<NSIDPayload>,
        admission: AdmissionConfig,
    ) -> Self {
        let mut access = AccessControl::default();
        access.insert_deny(denied_networks);
        access.insert_allow(allowed_networks);

        Self {
            context: Arc::new(ServerContext {
                handler,
                max_payload_size,
                nsid,
                access,
                admission: Admission::new(admission),
                shutdown: CancellationToken::new(),
            }),
            join_set: JoinSet::new(),
        }
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket(&mut self, socket: net::UdpSocket, receive_buffer_size: u16) {
        self.join_set.spawn(handle_udp(
            socket,
            receive_buffer_size,
            self.context.clone(),
        ));
    }

    /// Register a TcpListener to the Server. This should already be bound to either an IPv6 or an
    ///  IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP socket
    /// * `stream_timeout` - timeout duration of incoming requests, any connection that does not
    ///   send requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `response_buffer_size` - size of the buffer for outgoing responses per connection
    pub fn register_listener(
        &mut self,
        listener: net::TcpListener,
        stream_timeout: Option<Duration>,
        response_buffer_size: usize,
    ) {
        self.join_set.spawn(handle_tcp(
            listener,
            stream_timeout,
            response_buffer_size,
            self.context.clone(),
        ));
    }

    /// Register a TlsListener to the Server. The TlsListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// The TLS `ServerConfig` should be configured with TLS 1.3 support and the DoT ALPN protocol
    /// enabled.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `handshake_timeout` - timeout for performing TLS handshakes
    /// * `stream_timeout` - timeout duration of incoming requests, any connection that does not
    ///   send requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `tls_config` - rustls server config
    #[cfg(feature = "__tls")]
    pub fn register_tls_listener_with_tls_config(
        &mut self,
        listener: net::TcpListener,
        handshake_timeout: Option<Duration>,
        stream_timeout: Option<Duration>,
        tls_config: Arc<ServerConfig>,
    ) -> io::Result<()> {
        self.join_set.spawn(handle_tls(
            listener,
            tls_config,
            handshake_timeout,
            stream_timeout,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Register a TlsListener to the Server by providing a rustls `ResolvesServerCert`. The
    /// TlsListener should already be bound to either an IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `handshake_timeout` - timeout for performing TLS handshakes
    /// * `stream_timeout` - timeout duration of incoming requests, any connection that does not
    ///   send requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `server_cert_resolver` - resolver for the certificate and key used to announce to clients
    #[cfg(feature = "__tls")]
    pub fn register_tls_listener(
        &mut self,
        listener: net::TcpListener,
        handshake_timeout: Option<Duration>,
        stream_timeout: Option<Duration>,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> io::Result<()> {
        Self::register_tls_listener_with_tls_config(
            self,
            listener,
            handshake_timeout,
            stream_timeout,
            Arc::new(default_tls_server_config(b"dot", server_cert_resolver)?),
        )
    }

    /// Register a TcpListener for HTTPS (h2) to the Server for supporting DoH (DNS-over-HTTPS). The TcpListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `handshake_timeout` - timeout for performing TLS handshakes
    /// * `idle_timeout` - timeout before closing an idle connection
    /// * `request_timeout` - timeout for receiving a complete request over a request stream
    /// * `server_cert_resolver` - resolver for the certificate and key used to announce to clients
    /// * `dns_hostname` - the DNS hostname of the H2 server.
    /// * `http_endpoint` - the HTTP endpoint of the H2 server.
    #[cfg(feature = "__https")]
    #[allow(clippy::too_many_arguments)]
    pub fn register_https_listener(
        &mut self,
        listener: net::TcpListener,
        handshake_timeout: Option<Duration>,
        idle_timeout: Option<Duration>,
        request_timeout: Option<Duration>,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
        dns_hostname: Option<String>,
        http_endpoint: String,
    ) -> io::Result<()> {
        self.join_set.spawn(h2_handler::handle_h2(
            listener,
            handshake_timeout,
            idle_timeout,
            request_timeout,
            server_cert_resolver,
            dns_hostname,
            http_endpoint,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Register a TcpListener for HTTPS (h2) for supporting DoH with the given TLS config.
    ///
    /// The TcpListener should already be bound to either an IPv6 or an IPv4 address.
    ///
    /// The TLS `ServerConfig` should be configured with TLS 1.3 support and the DoH ALPN protocol
    /// enabled.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `handshake_timeout` - timeout for performing TLS handshakes
    /// * `idle_timeout` - timeout before closing an idle connection
    /// * `request_timeout` - timeout for receiving a complete request over a request stream
    /// * `tls_config` - a customized `ServerConfig` to use for TLS.
    /// * `dns_hostname` - the DNS hostname of the H2 server.
    /// * `http_endpoint` - the HTTP endpoint of the H2 server.
    #[cfg(feature = "__https")]
    #[allow(clippy::too_many_arguments)]
    pub fn register_https_listener_with_tls_config(
        &mut self,
        listener: net::TcpListener,
        handshake_timeout: Option<Duration>,
        idle_timeout: Option<Duration>,
        request_timeout: Option<Duration>,
        tls_config: Arc<ServerConfig>,
        dns_hostname: Option<String>,
        http_endpoint: String,
    ) -> io::Result<()> {
        self.join_set.spawn(h2_handler::handle_h2_with_acceptor(
            listener,
            handshake_timeout,
            idle_timeout,
            request_timeout,
            TlsAcceptor::from(tls_config),
            dns_hostname,
            http_endpoint,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Register a UdpSocket to the Server for supporting DoQ (DNS-over-QUIC). The UdpSocket should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `socket` - a bound UDP socket
    /// * `handshake_timeout` - timeout for performing QUIC handshakes
    /// * `idle_timeout` - timeout before closing an idle connection
    /// * `request_timeout` - timeout for receiving a complete request over a stream
    /// * `server_cert_resolver` - resolver for certificate and key used to announce to clients
    /// * `dns_hostname` - the DNS hostname of the DoQ server.
    #[cfg(feature = "__quic")]
    pub fn register_quic_listener(
        &mut self,
        socket: net::UdpSocket,
        handshake_timeout: Option<Duration>,
        idle_timeout: Option<Duration>,
        request_timeout: Option<Duration>,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> io::Result<()> {
        let cx = self.context.clone();
        self.join_set.spawn(quic_handler::handle_quic(
            socket,
            handshake_timeout,
            idle_timeout,
            request_timeout,
            server_cert_resolver,
            cx,
        ));
        Ok(())
    }

    /// Register a UdpSocket for supporting DoQ (DNS-over-QUIC) with the provided TLS config.
    ///
    /// The UdpSocket should already be bound to either an IPv6 or an IPv4 address.
    ///
    /// The TLS `ServerConfig` should be configured with TLS 1.3 support and the DoQ ALPN protocol
    /// enabled.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `socket` - a bound UDP socket
    /// * `handshake_timeout` - timeout for performing QUIC handshakes
    /// * `idle_timeout` - timeout before closing an idle connection
    /// * `request_timeout` - timeout for receiving a complete request over a stream
    /// * `tls_config` - a customized ServerConfig to use for TLS.
    /// * `dns_hostname` - the DNS hostname of the DoQ server.
    #[cfg(feature = "__quic")]
    pub fn register_quic_listener_and_tls_config(
        &mut self,
        socket: net::UdpSocket,
        handshake_timeout: Option<Duration>,
        idle_timeout: Option<Duration>,
        request_timeout: Option<Duration>,
        tls_config: Arc<ServerConfig>,
    ) -> Result<(), NetError> {
        let cx = self.context.clone();

        self.join_set.spawn(quic_handler::handle_quic_with_server(
            QuicServer::with_socket_and_tls_config(socket, tls_config)?,
            handshake_timeout,
            idle_timeout,
            request_timeout,
            cx,
        ));
        Ok(())
    }

    /// Register a UdpSocket to the Server for supporting DoH3 (DNS-over-HTTP/3). The UdpSocket should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `handshake_timeout` - timeout for performing QUIC handshakes
    /// * `idle_timeout` - timeout before closing an idle connection
    /// * `request_timeout` - timeout for receiving a complete request over a stream
    /// * `server_cert_resolver` - resolver for certificate and key used to announce to clients
    #[cfg(feature = "__h3")]
    #[allow(clippy::too_many_arguments)]
    pub fn register_h3_listener(
        &mut self,
        socket: net::UdpSocket,
        handshake_timeout: Option<Duration>,
        idle_timeout: Option<Duration>,
        request_timeout: Option<Duration>,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
        dns_hostname: Option<String>,
        http_endpoint: String,
    ) -> io::Result<()> {
        self.join_set.spawn(h3_handler::handle_h3(
            socket,
            handshake_timeout,
            idle_timeout,
            request_timeout,
            server_cert_resolver,
            dns_hostname,
            http_endpoint,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Register a UdpSocket for supporting DoH3 (DNS-over-HTTP/3) with the specified TLS config.
    ///
    /// The UdpSocket should already be bound to either an IPv6 or an IPv4 address.
    ///
    /// The TLS `ServerConfig` should be configured with TLS 1.3 support and the DoH3 ALPN protocol
    /// enabled.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `handshake_timeout` - timeout for performing QUIC handshakes
    /// * `idle_timeout` - timeout before closing an idle connection
    /// * `request_timeout` - timeout for receiving a complete request over a stream
    /// * `tls_config` - a customized ServerConfig to use for TLS.
    #[cfg(feature = "__h3")]
    #[allow(clippy::too_many_arguments)]
    pub fn register_h3_listener_with_tls_config(
        &mut self,
        socket: net::UdpSocket,
        handshake_timeout: Option<Duration>,
        idle_timeout: Option<Duration>,
        request_timeout: Option<Duration>,
        tls_config: Arc<ServerConfig>,
        dns_hostname: Option<String>,
        http_endpoint: String,
    ) -> Result<(), NetError> {
        self.join_set.spawn(h3_handler::handle_h3_with_server(
            H3Server::with_socket_and_tls_config(socket, tls_config)?,
            handshake_timeout,
            idle_timeout,
            request_timeout,
            dns_hostname,
            http_endpoint,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Triggers a graceful shutdown the server. All background tasks will stop accepting
    /// new connections and the returned future will complete once all tasks have terminated.
    pub async fn shutdown_gracefully(&mut self) -> Result<(), NetError> {
        self.context.shutdown.cancel();

        // Wait for the server to complete.
        self.block_until_done().await
    }

    /// Returns a reference to the [`CancellationToken`] used to gracefully shut down the server.
    ///
    /// Once cancellation is requested, all background tasks will stop accepting new connections,
    /// and `block_until_done()` will complete once all tasks have terminated.
    pub fn shutdown_token(&self) -> &CancellationToken {
        &self.context.shutdown
    }

    /// This will run until all background tasks complete. If one or more tasks return an error,
    /// one will be chosen as the returned error for this future.
    pub async fn block_until_done(&mut self) -> Result<(), NetError> {
        if self.join_set.is_empty() {
            warn!("block_until_done called with no pending tasks");
            return Ok(());
        }

        let mut out = Ok(());
        while let Some(join_result) = self.join_set.join_next().await {
            match join_result {
                Ok(Ok(())) => continue,
                Ok(Err(e)) => out = Err(e),
                Err(e) => return Err(NetError::from(format!("internal error in spawn: {e}"))),
            }
        }

        out
    }
}

async fn handle_udp(
    socket: net::UdpSocket,
    receive_buffer_size: u16,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    debug!("registering udp: {:?}", socket);

    // create the new UdpStream, the IP address isn't relevant, and ideally goes essentially no where.
    //   the address used is acquired from the inbound queries
    let (mut stream, stream_handle) = UdpStream::with_bound(
        socket,
        ([127, 255, 255, 254], 0).into(),
        receive_buffer_size,
    );

    let mut inner_join_set = JoinSet::new();
    loop {
        let Some(option) = cx.shutdown.run_until_cancelled(stream.next()).await else {
            // Graceful shutdown
            break;
        };
        let Some(message_res) = option else {
            // End of stream
            break;
        };

        let message = match message_res {
            Err(error) => {
                warn!(%error, "error receiving message on udp_socket");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                continue;
            }
            Ok(message) => message,
        };

        let src_addr = message.addr();
        debug!("received udp request from: {}", src_addr);

        // verify that the src address is safe for responses
        if let Err(e) = sanitize_src_address(src_addr) {
            warn!(
                "address can not be responded to {src_addr}: {e}",
                src_addr = src_addr,
                e = e
            );
            continue;
        }

        let cx = cx.clone();
        let stream_handle = stream_handle.with_remote_addr(src_addr);
        inner_join_set.spawn(async move {
            cx.handle_raw_request(message, Protocol::Udp, stream_handle)
                .await;
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
        Err(NetError::from("unexpected close of UDP socket"))
    }
}

async fn handle_tcp(
    listener: net::TcpListener,
    stream_timeout: Option<Duration>,
    response_buffer_size: usize,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    debug!("register tcp: {listener:?}");
    let mut inner_join_set = JoinSet::new();
    loop {
        let Some(result) = cx.shutdown.run_until_cancelled(listener.accept()).await else {
            // A graceful shutdown was initiated. Break out of the loop.
            break;
        };
        let (tcp_stream, src_addr) = match result {
            Ok((tcp_stream, src_addr)) => (tcp_stream, src_addr),
            Err(error) => {
                debug!(%error, "error receiving TCP tcp_stream error");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                continue;
            }
        };

        // verify that the src address is safe for responses
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(
                %src_addr, %error,
                "address can not be responded to (TCP)",
            );
            continue;
        }

        // and spawn to the io_loop
        let cx = cx.clone();
        inner_join_set.spawn(async move {
            debug!(%src_addr, "accepted TCP request");
            // take the created stream...
            let (buf_stream, stream_handle) = TcpStream::from_stream_with_buffer_size(
                AsyncIoTokioAsStd(tcp_stream),
                src_addr,
                response_buffer_size,
            );
            let mut timeout_stream = TimeoutStream::new(buf_stream, stream_timeout);

            while let Some(message) = timeout_stream.next().await {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => {
                        debug!(%src_addr, %error, "error in TCP request stream");
                        // we're going to bail on this connection...
                        return;
                    }
                };

                // we don't spawn here to limit clients from getting too many resources
                cx.handle_raw_request(message, Protocol::Tcp, stream_handle.clone())
                    .await;
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        Err(NetError::from("unexpected close of socket"))
    }
}

#[cfg(feature = "__tls")]
async fn handle_tls(
    listener: net::TcpListener,
    tls_config: Arc<ServerConfig>,
    handshake_timeout: Option<Duration>,
    stream_timeout: Option<Duration>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    debug!(?listener, "registered tls");
    let tls_acceptor = TlsAcceptor::from(tls_config);

    let mut inner_join_set = JoinSet::new();
    loop {
        let Some(result) = cx.shutdown.run_until_cancelled(listener.accept()).await else {
            // A graceful shutdown was initiated. Break out of the loop.
            break;
        };
        let (tcp_stream, src_addr) = match result {
            Ok((tcp_stream, src_addr)) => (tcp_stream, src_addr),
            Err(error) => {
                debug!(%error, "error receiving TLS tcp_stream error");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                continue;
            }
        };

        // verify that the src address is safe for responses
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(
                %src_addr, %error,
                "address can not be responded to (TLS)",
            );
            continue;
        }

        let cx = cx.clone();
        let tls_acceptor = tls_acceptor.clone();
        // kick out to a different task immediately, let them do the TLS handshake
        inner_join_set.spawn(async move {
            debug!(%src_addr, "starting TLS request");

            // perform the TLS
            let Ok(tls_stream) =
                optional_timeout(handshake_timeout, tls_acceptor.accept(tcp_stream)).await
            else {
                warn!("tls timeout expired during handshake");
                return;
            };

            let tls_stream = match tls_stream {
                Ok(tls_stream) => AsyncIoTokioAsStd(tls_stream),
                Err(error) => {
                    debug!(%src_addr, %error, "tls handshake error");
                    return;
                }
            };
            debug!(%src_addr, "accepted TLS request");
            let (buf_stream, stream_handle) = tls_from_stream(tls_stream, src_addr);
            let mut timeout_stream = TimeoutStream::new(buf_stream, stream_timeout);
            while let Some(message) = timeout_stream.next().await {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => {
                        debug!(
                            %src_addr, %error,
                            "error in TLS request stream",
                        );

                        // kill this connection
                        return;
                    }
                };

                cx.handle_raw_request(message, Protocol::Tls, stream_handle.clone())
                    .await;
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        Err(NetError::from("unexpected close of socket"))
    }
}

/// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
fn reap_tasks(join_set: &mut JoinSet<()>) {
    while join_set.try_join_next().is_some() {}
}

/// Construct a default `ServerConfig` for the given ALPN protocol and server cert resolver.
#[cfg(feature = "__tls")]
pub fn default_tls_server_config(
    protocol: &[u8],
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
) -> io::Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(server_cert_resolver);

    config.alpn_protocols = vec![protocol.to_vec()];

    Ok(config)
}

/// Configuration for inbound request admission control.
///
/// Admission control bounds the number of requests that the request handler processes
/// concurrently. It is applied after a request has been parsed and its client has passed the
/// access control checks, so malformed requests, unsupported opcodes and disallowed clients never
/// occupy a slot. All transports (UDP, TCP, DoT, DoH and DoQ) funnel through that single point.
///
/// A request that arrives while the limit is reached is either answered with `REFUSED` or
/// dropped without a response, see [`OverflowPolicy`]. Permits are released when the handler
/// future completes *or* when it is dropped, e.g. during shutdown, so the limit can not leak.
///
/// Note that long-running transactions, such as AXFR/IXFR zone transfers, hold their permit for
/// the entire transfer; size `max_concurrent_requests` with those in mind.
///
/// The default configuration disables admission control entirely, which matches the behaviour of
/// earlier releases.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionConfig {
    /// The maximum number of requests that may be handled concurrently.
    ///
    /// `0` (the default) disables admission control: no semaphore is allocated and requests are
    /// handled exactly as before.
    pub max_concurrent_requests: usize,
    /// The action taken when a request arrives while `max_concurrent_requests` are already in
    /// flight.
    ///
    /// This setting has no effect while `max_concurrent_requests` is `0`.
    pub overflow: OverflowPolicy,
}

/// The action taken for an inbound request that arrives while the server is at its configured
/// concurrency limit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OverflowPolicy {
    /// Answer the request with `RCODE=REFUSED`, so that the client learns the server is at
    /// capacity. This is the default.
    #[default]
    Refused,
    /// Send no response at all. This avoids spending resources on a response when the server is
    /// overloaded, at the cost of the client having to time out.
    Drop,
}

/// Admission control state, shared by all transports through [`ServerContext`].
struct Admission {
    /// Bounds the number of concurrently handled requests, `None` when admission control is
    /// disabled.
    semaphore: Option<Arc<Semaphore>>,
    /// The action to take when `semaphore` has no permits left.
    overflow: OverflowPolicy,
    #[cfg(feature = "metrics")]
    metrics: AdmissionMetrics,
}

impl Admission {
    fn new(config: AdmissionConfig) -> Self {
        let semaphore = match config.max_concurrent_requests {
            0 => None,
            max_concurrent_requests => Some(Arc::new(Semaphore::new(max_concurrent_requests))),
        };

        Self {
            semaphore,
            overflow: config.overflow,
            #[cfg(feature = "metrics")]
            metrics: AdmissionMetrics::new(),
        }
    }

    /// Attempts to reserve a slot for one request, without ever waiting.
    ///
    /// * `Ok(None)` - admission control is disabled, the request may proceed unconstrained.
    /// * `Ok(Some(permit))` - the request may proceed while the permit is held.
    /// * `Err(())` - the server is at capacity; the caller applies [`Admission::overflow`].
    fn try_acquire(&self) -> Result<Option<AdmissionPermit>, ()> {
        let Some(semaphore) = self.semaphore.as_ref() else {
            return Ok(None);
        };

        let permit = Arc::clone(semaphore).try_acquire_owned().map_err(|_| ())?;
        #[cfg(feature = "metrics")]
        self.metrics.inflight_acquired();

        Ok(Some(AdmissionPermit {
            _permit: permit,
            #[cfg(feature = "metrics")]
            metrics: self.metrics.clone(),
        }))
    }

    /// Records that a request was answered with `REFUSED` because of admission control.
    fn note_refused(&self) {
        #[cfg(feature = "metrics")]
        self.metrics.refused();
    }

    /// Records that a request was dropped because of admission control.
    fn note_dropped(&self) {
        #[cfg(feature = "metrics")]
        self.metrics.dropped();
    }
}

/// A slot reserved for one in-flight request.
///
/// The semaphore permit is released when this value is dropped, which includes the request future
/// being dropped before it completes. When the `metrics` feature is enabled this also keeps the
/// in-flight gauge accurate.
struct AdmissionPermit {
    /// Returning this permit to the semaphore is the whole point of the type.
    _permit: OwnedSemaphorePermit,
    #[cfg(feature = "metrics")]
    metrics: AdmissionMetrics,
}

#[cfg(feature = "metrics")]
impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.metrics.inflight_released();
    }
}

struct ServerContext<T> {
    handler: T,
    nsid: Option<NSIDPayload>,
    /// The server's UDP payload size.
    ///
    /// This should match the server's receive buffer size. This value will be used in outgoing EDNS
    /// pseudo-records.
    max_payload_size: u16,
    access: AccessControl,
    admission: Admission,
    shutdown: CancellationToken,
}

impl<T: RequestHandler> ServerContext<T> {
    async fn handle_raw_request(
        &self,
        message: SerialMessage,
        protocol: Protocol,
        mut stream_handle: BufDnsStreamHandle,
    ) {
        let (message, src_addr) = message.into_parts();
        let Some((info, reporter)) = self
            .handle_request(Bytes::from(message), src_addr, protocol)
            .await
        else {
            return;
        };

        match stream_handle.send(SerialMessage::new(info.bytes, src_addr)) {
            Ok(()) => reporter.report(&info.header),
            Err(error) => warn!(%error, "failed to send response"),
        }
    }

    /// Decodes and handles a request
    async fn handle_request(
        &self,
        message_bytes: Bytes,
        src_addr: SocketAddr,
        protocol: Protocol,
    ) -> Option<(ResponseInfo, ResponseReporter)> {
        let mut decoder = BinDecoder::new(&message_bytes);
        let Ok(header) = Header::read(&mut decoder) else {
            // This will only fail if the message is less than twelve bytes long. Such messages are
            // definitely not valid DNS queries, so it should be fine to return without sending a
            // response.
            return None;
        };

        if header.metadata.message_type == MessageType::Response {
            // Don't process response messages to avoid DoS attacks from reflection.
            return None;
        }

        if matches!(header.metadata.op_code, OpCode::Unknown(_)) {
            return Some(error_response(
                protocol,
                src_addr,
                header,
                None,
                ResponseCode::NotImp,
                None,
                "unsupported op code",
            ));
        }

        let queries = match Queries::read(&mut decoder, header.counts.queries as usize) {
            Ok(queries) => queries,
            Err(error) => {
                return Some(error_response(
                    protocol,
                    src_addr,
                    header,
                    None,
                    ResponseCode::FormErr,
                    None,
                    error,
                ));
            }
        };

        if !self.access.allow(src_addr.ip()) {
            info!(
                "request:Refused src:{proto}://{addr}#{port}",
                proto = protocol,
                addr = src_addr.ip(),
                port = src_addr.port(),
            );

            return Some(error_response(
                protocol,
                src_addr,
                header,
                Some(queries),
                ResponseCode::Refused,
                None,
                "request refused",
            ));
        }

        // Attempt to decode the message
        let request = match MessageRequest::read_with_queries(&mut decoder, queries.clone(), header)
        {
            Ok(message) => {
                let response_edns = match message.edns.as_ref() {
                    Some(edns) => {
                        let (rsp_edns, result) =
                            Edns::for_response(edns, self.max_payload_size, self.nsid.as_ref());
                        match result {
                            Ok(()) => Some(rsp_edns),
                            Err(code) => {
                                return Some(error_response(
                                    protocol,
                                    src_addr,
                                    header,
                                    Some(queries),
                                    code,
                                    Some(&rsp_edns),
                                    "request refused",
                                ));
                            }
                        }
                    }
                    None => None,
                };

                Request {
                    message,
                    response_edns,
                    raw: message_bytes,
                    src: src_addr,
                    protocol,
                }
            }
            Err(error) => {
                return Some(error_response(
                    protocol,
                    src_addr,
                    header,
                    Some(queries),
                    ResponseCode::FormErr,
                    None,
                    error,
                ));
            }
        };

        let id = request.message.metadata.id;
        let qflags = request.message.metadata.flags();
        let qop_code = request.message.metadata.op_code;
        let message_type = request.message.metadata.message_type;
        let is_dnssec = request
            .message
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);

        debug!(
            "request:{id} src:{proto}://{addr}#{port} type:{message_type} dnssec:{is_dnssec} {op} qflags:{qflags}",
            id = id,
            proto = request.protocol(),
            addr = request.src().ip(),
            port = request.src().port(),
            message_type = message_type,
            is_dnssec = is_dnssec,
            op = qop_code,
            qflags = qflags
        );

        let query = &*request.message.queries;
        debug!(
            "query:{query}:{qtype}:{class}",
            query = query.name(),
            qtype = query.query_type(),
            class = query.query_class(),
        );

        // Admission control is the single gate for all transports. The error paths above
        // (malformed messages, unsupported op codes, access control and EDNS version errors)
        // have already been answered and never occupy a slot.
        let _admission_permit = match self.admission.try_acquire() {
            Ok(permit) => permit,
            Err(()) => {
                return match self.admission.overflow {
                    OverflowPolicy::Refused => {
                        self.admission.note_refused();
                        Some(error_response(
                            protocol,
                            src_addr,
                            header,
                            Some(queries),
                            ResponseCode::Refused,
                            request.response_edns.as_ref(),
                            "admission control: server at capacity",
                        ))
                    }
                    OverflowPolicy::Drop => {
                        self.admission.note_dropped();
                        None
                    }
                };
            }
        };

        // The reporter will handle making sure to log the result of the request
        let reporter = ResponseReporter {
            request_meta: request.metadata,
            query: Some(query.clone()),
            protocol: request.protocol(),
            src_addr: request.src(),
            #[cfg(feature = "metrics")]
            metrics: ResponseHandlerMetrics::default(),
        };

        let info = self.handler.handle_request::<TokioTime>(&request).await;
        Some((info, reporter))
    }
}

// method to build an error response for the client
fn error_response(
    protocol: Protocol,
    src_addr: SocketAddr,
    header: Header,
    queries: Option<Queries>,
    response_code: ResponseCode,
    response_edns: Option<&Edns>,
    error: impl fmt::Display,
) -> (ResponseInfo, ResponseReporter) {
    // debug for more info on why the message parsing failed
    debug!(
        "request:{id} src:{proto}://{addr}#{port} type:{message_type} {op}:{response_code}:{error}",
        id = header.id,
        proto = protocol,
        addr = src_addr.ip(),
        port = src_addr.port(),
        message_type = header.message_type,
        op = header.op_code,
        response_code = response_code,
        error = error,
    );

    // The reporter will handle making sure to log the result of the request
    let reporter = ResponseReporter {
        request_meta: header.metadata,
        query: queries.as_ref().map(|q| (**q).clone()),
        protocol,
        src_addr,
        #[cfg(feature = "metrics")]
        metrics: ResponseHandlerMetrics::default(),
    };

    let response = match queries.as_ref() {
        Some(queries) => MessageResponseBuilder::new(queries, response_edns, None),
        None => MessageResponseBuilder::no_queries(response_edns),
    };

    (
        response.error_msg(&header, response_code).encode(protocol),
        reporter,
    )
}

pub(super) struct ResponseReporter {
    pub(super) request_meta: Metadata,
    query: Option<LowerQuery>,
    pub(super) protocol: Protocol,
    src_addr: SocketAddr,
    #[cfg(feature = "metrics")]
    metrics: ResponseHandlerMetrics,
}

impl ResponseReporter {
    /// Logs the response sent for the request, and updates metrics
    fn report(&self, header: &Header) {
        let id = self.request_meta.id;
        let rid = header.id;
        if id != rid {
            warn!("request id:{id} does not match response id:{rid}");
            debug_assert_eq!(id, rid, "request id and response id should match");
        }

        let rflags = header.flags();
        let counts = header.counts;
        info!(
            "request:{id} src:{proto}://{addr}#{port} {op} qflags:{qflags} response:{code:?} rr:{answers}/{authorities}/{additionals} rflags:{rflags}",
            id = rid,
            proto = self.protocol,
            addr = self.src_addr.ip(),
            port = self.src_addr.port(),
            op = self.request_meta.op_code,
            qflags = self.request_meta.flags(),
            code = header.response_code,
            answers = counts.answers,
            authorities = counts.authorities,
            additionals = counts.additionals,
            rflags = rflags
        );

        if let Some(query) = &self.query {
            info!(
                "query:{query}:{qtype}:{class}",
                query = query.name(),
                qtype = query.query_type(),
                class = query.query_class(),
            );
        }

        #[cfg(feature = "metrics")]
        self.metrics.update(header, self);
    }
}

/// Checks if the IP address is safe for returning messages
///
/// Examples of unsafe addresses are any with a port of `0`
///
/// # Returns
///
/// Error if the address should not be used for returned requests
fn sanitize_src_address(src: SocketAddr) -> Result<(), String> {
    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    if src.port() == 0 {
        return Err(format!("cannot respond to src on port 0: {src}"));
    }

    fn verify_v4(src: Ipv4Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v4 addr: {src}"));
        }

        if src.is_broadcast() {
            return Err(format!("cannot respond to broadcast v4 addr: {src}"));
        }

        // TODO: add check for is_reserved when that stabilizes

        Ok(())
    }

    fn verify_v6(src: Ipv6Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v6 addr: {src}"));
        }

        Ok(())
    }

    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    match src.ip() {
        IpAddr::V4(v4) => verify_v4(v4),
        IpAddr::V6(v6) => verify_v6(v6),
    }
}

/// Returns `true` if an `accept()` error means the listener itself is no longer usable.
fn is_unrecoverable_socket_error(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::NotConnected)
}

/// Optionally applies a timeout to a future.
#[cfg(any(
    feature = "__tls",
    feature = "__quic",
    feature = "__https",
    feature = "__h3"
))]
async fn optional_timeout<T>(
    timeout_opt: Option<Duration>,
    future: impl Future<Output = T>,
) -> Result<T, Elapsed> {
    match timeout_opt {
        Some(timeout_duration) => timeout(timeout_duration, future).await,
        None => Ok(future.await),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::op::{DEFAULT_MAX_PAYLOAD_LEN, HeaderCounts, Message, Query};
    use crate::proto::rr::{Name, RecordType};
    use crate::proto::serialize::binary::{BinEncodable, BinEncoder};
    use crate::zone_handler::Catalog;
    use futures_util::future;
    #[cfg(feature = "__tls")]
    use rustls::sign::SingleCertAndKey;
    use std::net::SocketAddr;
    #[cfg(feature = "__tls")]
    use test_support::TestCertificates;
    use test_support::subscribe;
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::time::timeout;

    #[tokio::test]
    async fn abort() {
        subscribe();

        let endpoints = Endpoints::new().await;

        let endpoints2 = endpoints.clone();
        let (abortable, abort_handle) = future::abortable(async move {
            let mut server_future = Server::new(Catalog::new());
            endpoints2.register(&mut server_future).await;
            server_future.block_until_done().await
        });

        abort_handle.abort();
        abortable.await.expect_err("expected abort");

        endpoints.rebind_all().await;
    }

    #[tokio::test]
    async fn graceful_shutdown() {
        subscribe();
        let mut server_future = Server::new(Catalog::new());
        let endpoints = Endpoints::new().await;
        endpoints.register(&mut server_future).await;

        timeout(Duration::from_secs(2), server_future.shutdown_gracefully())
            .await
            .expect("timed out waiting for the server to complete")
            .expect("error while awaiting tasks");

        endpoints.rebind_all().await;
    }

    #[test]
    fn test_sanitize_src_addr() {
        // ipv4 tests
        assert!(sanitize_src_address(SocketAddr::from(([192, 168, 1, 1], 4_096))).is_ok());
        assert!(sanitize_src_address(SocketAddr::from(([127, 0, 0, 1], 53))).is_ok());

        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0], 0))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([192, 168, 1, 1], 0))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0], 4_096))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([255, 255, 255, 255], 4_096))).is_err());

        // ipv6 tests
        assert!(
            sanitize_src_address(SocketAddr::from(([0x20, 0, 0, 0, 0, 0, 0, 0x1], 4_096))).is_ok()
        );
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 4_096))).is_ok());

        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 4_096))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))).is_err());
        assert!(
            sanitize_src_address(SocketAddr::from(([0x20, 0, 0, 0, 0, 0, 0, 0x1], 0))).is_err()
        );
    }

    #[derive(Clone)]
    struct Endpoints {
        udp_addr: SocketAddr,
        tcp_addr: SocketAddr,
        #[cfg(feature = "__tls")]
        rustls_addr: SocketAddr,
        #[cfg(feature = "__https")]
        https_rustls_addr: SocketAddr,
        #[cfg(feature = "__quic")]
        quic_addr: SocketAddr,
        #[cfg(feature = "__h3")]
        h3_addr: SocketAddr,
    }

    impl Endpoints {
        async fn new() -> Self {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "__tls")]
            let rustls = TcpListener::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "__https")]
            let https_rustls = TcpListener::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "__quic")]
            let quic = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "__h3")]
            let h3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            Self {
                udp_addr: udp.local_addr().unwrap(),
                tcp_addr: tcp.local_addr().unwrap(),
                #[cfg(feature = "__tls")]
                rustls_addr: rustls.local_addr().unwrap(),
                #[cfg(feature = "__https")]
                https_rustls_addr: https_rustls.local_addr().unwrap(),
                #[cfg(feature = "__quic")]
                quic_addr: quic.local_addr().unwrap(),
                #[cfg(feature = "__h3")]
                h3_addr: h3.local_addr().unwrap(),
            }
        }

        async fn register<T: RequestHandler>(&self, server: &mut Server<T>) {
            server.register_socket(
                UdpSocket::bind(self.udp_addr).await.unwrap(),
                DEFAULT_MAX_PAYLOAD_LEN,
            );
            server.register_listener(
                TcpListener::bind(self.tcp_addr).await.unwrap(),
                Some(Duration::from_secs(1)),
                32,
            );

            #[cfg(feature = "__tls")]
            {
                let cert_key = rustls_cert_key();
                server
                    .register_tls_listener(
                        TcpListener::bind(self.rustls_addr).await.unwrap(),
                        Some(Duration::from_secs(30)),
                        Some(Duration::from_secs(30)),
                        cert_key,
                    )
                    .unwrap();
            }

            #[cfg(feature = "__https")]
            {
                let cert_key = rustls_cert_key();
                server
                    .register_https_listener(
                        TcpListener::bind(self.https_rustls_addr).await.unwrap(),
                        Some(Duration::from_secs(1)),
                        Some(Duration::from_secs(1)),
                        Some(Duration::from_secs(1)),
                        cert_key,
                        None,
                        "/dns-query".into(),
                    )
                    .unwrap();
            }

            #[cfg(feature = "__quic")]
            {
                let cert_key = rustls_cert_key();
                server
                    .register_quic_listener(
                        UdpSocket::bind(self.quic_addr).await.unwrap(),
                        Some(Duration::from_secs(1)),
                        Some(Duration::from_secs(1)),
                        Some(Duration::from_secs(1)),
                        cert_key,
                    )
                    .unwrap();
            }

            #[cfg(feature = "__h3")]
            {
                let cert_key = rustls_cert_key();
                server
                    .register_h3_listener(
                        UdpSocket::bind(self.h3_addr).await.unwrap(),
                        Some(Duration::from_secs(1)),
                        Some(Duration::from_secs(1)),
                        Some(Duration::from_secs(1)),
                        cert_key,
                        None,
                        "/dns-query".into(),
                    )
                    .unwrap();
            }
        }

        async fn rebind_all(&self) {
            UdpSocket::bind(self.udp_addr).await.unwrap();
            TcpListener::bind(self.tcp_addr).await.unwrap();
            #[cfg(feature = "__tls")]
            TcpListener::bind(self.rustls_addr).await.unwrap();
            #[cfg(feature = "__https")]
            TcpListener::bind(self.https_rustls_addr).await.unwrap();
            #[cfg(feature = "__quic")]
            UdpSocket::bind(self.quic_addr).await.unwrap();
            #[cfg(feature = "__h3")]
            UdpSocket::bind(self.h3_addr).await.unwrap();
        }
    }

    #[cfg(feature = "__tls")]
    fn rustls_cert_key() -> Arc<dyn ResolvesServerCert> {
        Arc::new(SingleCertAndKey::from(
            TestCertificates::generate().certified_key(),
        ))
    }

    #[test]
    fn task_reap_on_empty_joinset() {
        let mut joinset = JoinSet::new();

        // this should return immediately
        reap_tasks(&mut joinset);
    }

    #[tokio::test]
    async fn task_reap_on_nonempty_joinset() {
        let mut joinset = JoinSet::new();
        let t = joinset.spawn(tokio::time::sleep(Duration::from_secs(2)));

        // this should return immediately since no task is ready
        reap_tasks(&mut joinset);
        t.abort();

        // this should also return immediately since the task has been aborted
        reap_tasks(&mut joinset);
    }

    /// A request handler that signals when it is entered and then waits until the test releases
    /// it, so that a request can be kept in flight while other requests are exercised.
    struct GatedHandler {
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        gate: Arc<Semaphore>,
    }

    #[async_trait::async_trait]
    impl RequestHandler for GatedHandler {
        async fn handle_request<T: crate::net::runtime::Time>(
            &self,
            _request: &Request,
        ) -> ResponseInfo {
            let _ = self.entered.send(());
            let _ = self.gate.acquire().await;

            ResponseInfo {
                header: Header {
                    metadata: Metadata::new(0x1234, MessageType::Response, OpCode::Query),
                    counts: HeaderCounts::default(),
                },
                cache_ttl: None,
                bytes: Vec::new(),
            }
        }
    }

    /// Drives one request through the server context, the way a transport task does.
    async fn dispatch(
        cx: Arc<ServerContext<GatedHandler>>,
        bytes: Bytes,
        src: SocketAddr,
    ) -> Option<(ResponseInfo, ResponseReporter)> {
        cx.handle_request(bytes, src, Protocol::Udp).await
    }

    /// Encodes a minimal, well formed query.
    fn query_bytes() -> Bytes {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.add_query(Query::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        let mut bytes = Vec::new();
        message
            .emit(&mut BinEncoder::new(&mut bytes))
            .expect("failed to encode query");
        Bytes::from(bytes)
    }

    fn admission_context(
        max_concurrent_requests: usize,
        overflow: OverflowPolicy,
    ) -> (
        Arc<ServerContext<GatedHandler>>,
        Arc<Semaphore>,
        tokio::sync::mpsc::UnboundedReceiver<()>,
    ) {
        let (entered, entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(0));

        let server = Server::with_access_and_admission(
            GatedHandler {
                entered,
                gate: gate.clone(),
            },
            [],
            [],
            DEFAULT_MAX_PAYLOAD_LEN,
            None,
            AdmissionConfig {
                max_concurrent_requests,
                overflow,
            },
        );

        (server.context.clone(), gate, entered_rx)
    }

    #[test]
    fn admission_disabled_never_limits() {
        let admission = Admission::new(AdmissionConfig::default());

        // Without a limit no semaphore is allocated and callers are told to proceed.
        for _ in 0..3 {
            let permit = admission
                .try_acquire()
                .expect("disabled admission control can not refuse");
            assert!(permit.is_none());
        }
    }

    #[test]
    fn admission_limit_is_released_with_the_permit() {
        let admission = Admission::new(AdmissionConfig {
            max_concurrent_requests: 1,
            overflow: OverflowPolicy::Refused,
        });

        let first = admission.try_acquire().expect("first request is admitted");
        assert!(first.is_some());
        assert!(
            admission.try_acquire().is_err(),
            "second request must not exceed the limit"
        );

        // Dropping the permit (e.g. a cancelled request future) releases the slot again.
        drop(first);
        let second = admission
            .try_acquire()
            .expect("permit is returned when dropped");
        assert!(second.is_some());
    }

    #[tokio::test]
    async fn handle_request_refuses_when_at_capacity() {
        subscribe();

        let (cx, gate, mut entered) = admission_context(1, OverflowPolicy::Refused);
        let src: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 53_000));
        let bytes = query_bytes();

        // The first request takes the single slot and parks inside the handler.
        let first = tokio::spawn(dispatch(cx.clone(), bytes.clone(), src));
        entered
            .recv()
            .await
            .expect("first request reached the handler");

        // Error responses are produced before the admission gate, so a malformed request is still
        // answered with FORMERR while the server is at capacity.
        let malformed = Bytes::from_static(&[
            0x00, 0x00, // id
            0x00, 0x00, // flags: query, opcode QUERY
            0x00, 0x01, // QDCOUNT: one query, but the message ends here
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ]);
        let (info, _reporter) = cx
            .handle_request(malformed, src, Protocol::Udp)
            .await
            .expect("malformed requests are still answered");
        assert_eq!(info.header.response_code, ResponseCode::FormErr);

        // A well formed request is refused without ever reaching the handler.
        let (info, _reporter) = cx
            .handle_request(bytes.clone(), src, Protocol::Udp)
            .await
            .expect("a refused request still produces a response");
        assert_eq!(info.header.response_code, ResponseCode::Refused);

        // Releasing the first request returns the slot to the pool.
        gate.add_permits(1);
        let (info, _reporter) = first
            .await
            .expect("first request task panicked")
            .expect("first request produced a response");
        assert_eq!(info.header.response_code, ResponseCode::NoError);

        let third = tokio::spawn(dispatch(cx.clone(), bytes.clone(), src));
        entered
            .recv()
            .await
            .expect("slot was released when the first request completed");
        third.abort();
        let _ = third.await;
    }

    #[tokio::test]
    async fn handle_request_drops_when_at_capacity() {
        subscribe();

        let (cx, gate, mut entered) = admission_context(1, OverflowPolicy::Drop);
        let src: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 53_000));
        let bytes = query_bytes();

        let first = tokio::spawn(dispatch(cx.clone(), bytes.clone(), src));
        entered
            .recv()
            .await
            .expect("first request reached the handler");

        assert!(
            cx.handle_request(bytes, src, Protocol::Udp).await.is_none(),
            "the drop policy must not produce a response"
        );

        gate.add_permits(1);
        let _ = first.await.expect("first request task panicked");
    }
}
