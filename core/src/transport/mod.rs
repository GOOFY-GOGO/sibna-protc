//! Relay Transport Architecture — SOCKS5/Tor Anonymity v3.0.1
//!
//! This module implements the `RelayClient`, the primary transport layer
//! for communicating with a Sibna Server. It supports:
//!
//! 1. **RESTful Prekey Sync**: HTTP uploading/fetching of hybrid bundles.
//! 2. **WebSocket Relay**: Real-time bi-directional message relay.
//! 3. **Tor/Proxy Anonymity**: Optional SOCKS5 tunneling for all traffic.

#[cfg(feature = "p2p")]
pub mod relay;

#[cfg(feature = "p2p")]
pub use relay::RelayClient;

/// Unified trait for secure transport layers (TLS, Noise, SOCKS5).
/// Sibna manages transport-level security at this layer.
pub trait SecureTransport: Send + Sync {
    /// Send an encrypted Sibna packet over the secure transport.
    fn send_packet(&self, data: &[u8]) -> crate::error::ProtocolResult<()>;
    /// Receive a packet from the transport.
    fn recv_packet(&self) -> crate::error::ProtocolResult<Vec<u8>>;
}
