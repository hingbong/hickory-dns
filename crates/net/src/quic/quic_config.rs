// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::time::Duration;

use quinn::{EndpointConfig, IdleTimeout, TransportConfig, VarInt};

use crate::error::NetError;

/// Optional overrides for the QUIC transport parameters used by Hickory's QUIC based transports,
/// DNS over QUIC (DoQ) and DNS over HTTP/3 (DoH3).
///
/// Hickory starts from quinn's `TransportConfig::default()` and then applies the protocol specific
/// stream limits (DoQ forbids the peer from opening streams, H3 allows the streams its control and
/// QPACK streams need). Every field here is optional: when a field is `None`, the value Hickory
/// would otherwise use is kept, so a default constructed `QuicTransportOptions` is a no-op.
///
/// The values quinn uses when no override is given are:
///
/// | Parameter | quinn default |
/// | --------- | ------------- |
/// | `stream_receive_window` | 1,250,000 bytes |
/// | `receive_window` | `VarInt::MAX` (2^62 - 1 bytes) |
/// | `send_window` | 10,000,000 bytes |
/// | `max_idle_timeout` | 30 seconds |
/// | `keep_alive_interval` | disabled |
///
/// `max_concurrent_bidi_streams` and `max_concurrent_uni_streams` default to 0 for DoQ and to 3
/// respectively 4 for H3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuicTransportOptions {
    /// Maximum number of bytes the peer may transmit on a single stream before it must wait for
    /// flow control credit.
    ///
    /// Must be greater than zero and at most `VarInt::MAX`. It should not exceed
    /// `receive_window`; a configuration where both are set and the per stream window is larger
    /// than the connection window is rejected by [`QuicTransportOptions::apply`].
    ///
    /// When unset, quinn's default of 1,250,000 bytes is used.
    pub stream_receive_window: Option<u64>,

    /// Maximum number of bytes the peer may transmit across all streams of a connection before it
    /// must wait for flow control credit.
    ///
    /// Must be greater than zero and at most `VarInt::MAX`.
    ///
    /// When unset, quinn's default of `VarInt::MAX` (i.e. no connection level limit) is used.
    pub receive_window: Option<u64>,

    /// Maximum number of bytes of outgoing data that may be buffered while waiting for the peer to
    /// acknowledge it.
    ///
    /// Must be greater than zero and at most `VarInt::MAX`. Lowering this bounds the memory used by
    /// in flight queries on a connection.
    ///
    /// When unset, quinn's default of 10,000,000 bytes is used.
    pub send_window: Option<u64>,

    /// Number of seconds of inactivity after which the connection is considered dead.
    ///
    /// `Some(0)` disables the idle timeout, so the connection is never closed for being idle.
    /// Leaving this unset keeps quinn's default of 30 seconds.
    ///
    /// Values that cannot be represented as a QUIC varint of milliseconds are rejected by
    /// [`QuicTransportOptions::apply`].
    pub max_idle_timeout: Option<u64>,

    /// Number of seconds of inactivity after which a keep-alive packet is sent to the peer.
    ///
    /// `Some(0)` disables keep-alives, as does leaving this unset, which is the current default.
    /// Enabling keep-alives keeps idle connections alive through stateful middleboxes at the cost
    /// of continuously waking both peers, so it is not enabled by default.
    pub keep_alive_interval: Option<u64>,

    /// Maximum number of concurrent bidirectional streams the *peer* may open towards us.
    ///
    /// This is a limit on the streams the remote endpoint may initiate, it is not a limit on how
    /// many queries we send concurrently: every DoQ query is sent on its own client initiated
    /// bidirectional stream, so this does not throttle outbound queries. Zero forbids the peer from
    /// opening any bidirectional stream.
    ///
    /// When unset, the protocol specific default is kept: 0 for DoQ and 3 for H3.
    pub max_concurrent_bidi_streams: Option<u64>,

    /// Maximum number of concurrent unidirectional streams the *peer* may open towards us.
    ///
    /// When unset, the protocol specific default is kept: 0 for DoQ and 4 for H3 (the control
    /// stream, the QPACK encoder and decoder streams, and a reserved GREASE stream).
    pub max_concurrent_uni_streams: Option<u64>,
}

impl QuicTransportOptions {
    /// Applies the options that are set to `config`, leaving every parameter that is `None`
    /// untouched.
    ///
    /// The options are validated up front, so a rejected configuration does not leave `config`
    /// partially updated.
    ///
    /// # Errors
    ///
    /// Returns a [`NetError`] when a window is zero or too large for a QUIC varint, when
    /// `stream_receive_window` exceeds `receive_window`, or when `max_idle_timeout` cannot be
    /// represented as a QUIC varint of milliseconds.
    pub fn apply(&self, config: &mut TransportConfig) -> Result<(), NetError> {
        // Validate and convert every option before touching `config`, so an invalid option cannot
        // leave the transport configuration half updated.
        let stream_receive_window = self
            .stream_receive_window
            .map(|value| Self::byte_window("stream_receive_window", value))
            .transpose()?;
        let receive_window = self
            .receive_window
            .map(|value| Self::byte_window("receive_window", value))
            .transpose()?;
        let send_window = self
            .send_window
            .map(|value| Self::byte_window("send_window", value))
            .transpose()?
            .map(u64::from);
        let max_idle_timeout = self.max_idle_timeout.map(Self::idle_timeout).transpose()?;
        let keep_alive_interval = self
            .keep_alive_interval
            .map(|seconds| (seconds > 0).then_some(Duration::from_secs(seconds)));
        let max_concurrent_bidi_streams = self
            .max_concurrent_bidi_streams
            .map(|value| Self::stream_count("max_concurrent_bidi_streams", value))
            .transpose()?;
        let max_concurrent_uni_streams = self
            .max_concurrent_uni_streams
            .map(|value| Self::stream_count("max_concurrent_uni_streams", value))
            .transpose()?;

        if let (Some(stream_receive_window), Some(receive_window)) =
            (self.stream_receive_window, self.receive_window)
        {
            if stream_receive_window > receive_window {
                return Err(NetError::from(format!(
                    "QUIC transport option `stream_receive_window` ({stream_receive_window}) must not exceed `receive_window` ({receive_window})"
                )));
            }
        }

        if let Some(value) = stream_receive_window {
            config.stream_receive_window(value);
        }
        if let Some(value) = receive_window {
            config.receive_window(value);
        }
        if let Some(value) = send_window {
            config.send_window(value);
        }
        if let Some(timeout) = max_idle_timeout {
            config.max_idle_timeout(timeout);
        }
        if let Some(interval) = keep_alive_interval {
            config.keep_alive_interval(interval);
        }
        if let Some(value) = max_concurrent_bidi_streams {
            config.max_concurrent_bidi_streams(value);
        }
        if let Some(value) = max_concurrent_uni_streams {
            config.max_concurrent_uni_streams(value);
        }

        Ok(())
    }

    /// Converts a byte count window, which must be representable as a QUIC varint and non-zero.
    fn byte_window(name: &str, value: u64) -> Result<VarInt, NetError> {
        if value == 0 {
            return Err(NetError::from(format!(
                "QUIC transport option `{name}` must be greater than zero"
            )));
        }

        Self::var_int(name, value)
    }

    /// Converts a stream count, where zero is a meaningful value: it forbids the peer from opening
    /// any stream.
    fn stream_count(name: &str, value: u64) -> Result<VarInt, NetError> {
        Self::var_int(name, value)
    }

    fn var_int(name: &str, value: u64) -> Result<VarInt, NetError> {
        VarInt::try_from(value).map_err(|_| {
            NetError::from(format!(
                "QUIC transport option `{name}` ({value}) exceeds the maximum of {}",
                u64::from(VarInt::MAX)
            ))
        })
    }

    /// Converts a timeout in seconds, where zero disables the timeout.
    fn idle_timeout(seconds: u64) -> Result<Option<IdleTimeout>, NetError> {
        if seconds == 0 {
            return Ok(None);
        }

        IdleTimeout::try_from(Duration::from_secs(seconds))
            .map(Some)
            .map_err(|_| {
                NetError::from(format!(
                    "QUIC transport option `max_idle_timeout` ({seconds} seconds) cannot be represented as a QUIC varint of milliseconds"
                ))
            })
    }
}

/// Returns a default endpoint configuration for DNS-over-QUIC
pub(crate) fn endpoint() -> EndpointConfig {
    // set some better EndpointConfig defaults for DoQ
    let mut endpoint_config = EndpointConfig::default();

    // all DNS packets have a maximum size of u16 due to DoQ and 1035 rfc
    // TODO: the RFC claims max == u16::max, but this matches the max in some test servers.
    endpoint_config
        .max_udp_payload_size(0x45ac)
        .expect("max udp payload size exceeded");

    endpoint_config
}

/// Returns a default endpoint configuration for DNS-over-QUIC
pub(crate) fn transport() -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport_config.datagram_receive_buffer_size(None);
    transport_config.datagram_send_buffer_size(0);

    transport_config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn debug(config: &TransportConfig) -> String {
        format!("{config:?}")
    }

    #[test]
    fn empty_options_keep_the_defaults() {
        let mut config = TransportConfig::default();
        QuicTransportOptions::default()
            .apply(&mut config)
            .expect("an empty configuration must be valid");

        assert_eq!(debug(&config), debug(&TransportConfig::default()));
    }

    #[test]
    fn applies_the_configured_values() {
        let options = QuicTransportOptions {
            stream_receive_window: Some(65_536),
            receive_window: Some(131_072),
            send_window: Some(262_144),
            max_idle_timeout: Some(60),
            keep_alive_interval: Some(15),
            max_concurrent_bidi_streams: Some(3),
            max_concurrent_uni_streams: Some(4),
        };

        let mut config = TransportConfig::default();
        options
            .apply(&mut config)
            .expect("the values are in range and must be accepted");

        let config = debug(&config);
        assert!(config.contains("stream_receive_window: 65536"), "{config}");
        assert!(config.contains("receive_window: 131072"), "{config}");
        assert!(config.contains("send_window: 262144"), "{config}");
        assert!(config.contains("max_idle_timeout: Some(60000)"), "{config}");
        assert!(
            config.contains("keep_alive_interval: Some(15s)"),
            "{config}"
        );
        assert!(
            config.contains("max_concurrent_bidi_streams: 3"),
            "{config}"
        );
        assert!(config.contains("max_concurrent_uni_streams: 4"), "{config}");
    }

    #[test]
    fn zero_idle_timeout_disables_the_timeout() {
        let options = QuicTransportOptions {
            max_idle_timeout: Some(0),
            ..Default::default()
        };

        let mut config = TransportConfig::default();
        options.apply(&mut config).expect("zero means disabled");

        let config = debug(&config);
        assert!(config.contains("max_idle_timeout: None"), "{config}");
    }

    #[test]
    fn zero_keep_alive_disables_keep_alives() {
        let options = QuicTransportOptions {
            keep_alive_interval: Some(0),
            ..Default::default()
        };

        let mut config = TransportConfig::default();
        options.apply(&mut config).expect("zero means disabled");

        let config = debug(&config);
        assert!(config.contains("keep_alive_interval: None"), "{config}");
    }

    #[test]
    fn rejects_zero_and_out_of_range_windows() {
        for options in [
            QuicTransportOptions {
                stream_receive_window: Some(0),
                ..Default::default()
            },
            QuicTransportOptions {
                receive_window: Some(0),
                ..Default::default()
            },
            QuicTransportOptions {
                send_window: Some(0),
                ..Default::default()
            },
            QuicTransportOptions {
                stream_receive_window: Some(u64::MAX),
                ..Default::default()
            },
            QuicTransportOptions {
                receive_window: Some(u64::MAX),
                ..Default::default()
            },
            QuicTransportOptions {
                send_window: Some(u64::MAX),
                ..Default::default()
            },
            QuicTransportOptions {
                max_concurrent_bidi_streams: Some(u64::MAX),
                ..Default::default()
            },
            QuicTransportOptions {
                max_concurrent_uni_streams: Some(u64::MAX),
                ..Default::default()
            },
            QuicTransportOptions {
                max_idle_timeout: Some(u64::MAX),
                ..Default::default()
            },
        ] {
            let mut config = TransportConfig::default();
            assert!(options.apply(&mut config).is_err(), "{options:?}");
        }
    }

    #[test]
    fn rejects_a_stream_window_larger_than_the_connection_window() {
        let options = QuicTransportOptions {
            stream_receive_window: Some(131_072),
            receive_window: Some(65_536),
            ..Default::default()
        };

        let mut config = TransportConfig::default();
        assert!(options.apply(&mut config).is_err());
    }
}
