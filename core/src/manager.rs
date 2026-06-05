//! Hybrid Routing Manager
//!
//! The `HybridRouter` coordinates between P2P direct transport and
//! Server-based relay transport. It implements a "P2P-first" policy.
//!
//! # Security Hardening Applied (v3.0.1 Fortress)
//!
//! | ID  | Severity | Description                                              | Status |
//! |-----|----------|----------------------------------------------------------|--------|
//! | F-01| CRITICAL | Race condition in discovery → DashMap entry API          | ✅     |
//! | F-02| CRITICAL | `unwrap_or_default()` on hex decode → ghost-peer DoS     | ✅     |
//! | F-03| HIGH     | No peer cap in `add_p2p_peer` → memory exhaustion DoS    | ✅     |
//! | F-04| HIGH     | `InternalErrorDetailed` leaks internal details to caller | ✅     |
//! | F-05| HIGH     | Discovery loop has no graceful shutdown/cancellation     | ✅     |
//! | F-06| MEDIUM   | No input size guard on `send_message`                    | ✅     |
//! | F-07| MEDIUM   | No peer-address validation before connecting             | ✅     |
//! | F-08| MEDIUM   | Cover-traffic delay uses uniform distribution            | ✅     |
//!
//! All findings F-01 through F-08 have been resolved in v3.0.1.
//! NOTE on original finding #3 (Signature Verification):
//! The `is_dummy` field IS already included in `signing_payload()` in
//! `metadata.rs` (line 121: `hasher.update(&[self.is_dummy as u8])`).
//! This was a FALSE POSITIVE in the original report. Verified and documented.

use crate::error::ProtocolError;
#[cfg(feature = "p2p")]
use crate::p2p::{P2pNode, Peer};
#[cfg(feature = "p2p")]
use crate::transport::relay::RelayClient;
use crate::{ProtocolResult, SecureContext};
#[cfg(feature = "p2p")]
use dashmap::DashMap;
#[cfg(feature = "p2p")]
use rand::Rng;
use std::sync::Arc;
use tracing::warn;
#[cfg(feature = "p2p")]
use tracing::{debug, info};

// ── Security constants ────────────────────────────────────────────────────────

/// Maximum number of active P2P peers.
/// Prevents memory exhaustion via mDNS flood attacks. (FIX F-03)
#[cfg(feature = "p2p")]
const MAX_ACTIVE_PEERS: usize = 500;

/// Maximum plaintext size accepted by `send_message`.
/// 64 MiB — prevents gigabyte-sized allocation attacks. (FIX F-06)
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Mean delay (seconds) for exponential cover-traffic distribution. (FIX F-08)
#[cfg(feature = "p2p")]
const COVER_TRAFFIC_MEAN_SECS: f64 = 5.0;

// ── HybridRouter ─────────────────────────────────────────────────────────────

/// Manages hybrid communication (P2P + Relay)
#[derive(Clone)]
pub struct HybridRouter {
    #[allow(dead_code)]
    ctx: SecureContext,
    #[cfg(feature = "p2p")]
    p2p_node: Option<Arc<P2pNode>>,
    #[cfg(feature = "p2p")]
    active_peers: Arc<DashMap<Vec<u8>, Arc<Peer>>>,
    cover_traffic_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Cancellation signal for the discovery background task. (FIX F-05)
    #[cfg(feature = "p2p")]
    discovery_cancel: Arc<tokio::sync::Notify>,
    /// Relay client for server-mediated message delivery.
    #[cfg(feature = "p2p")]
    relay_client: Option<Arc<RelayClient>>,
}

impl HybridRouter {
    pub fn new(ctx: SecureContext) -> Self {
        let router = Self {
            ctx,
            #[cfg(feature = "p2p")]
            p2p_node: None,
            #[cfg(feature = "p2p")]
            active_peers: Arc::new(DashMap::new()),
            cover_traffic_enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(feature = "p2p")]
            discovery_cancel: Arc::new(tokio::sync::Notify::new()),
            #[cfg(feature = "p2p")]
            relay_client: None,
        };

        // Start automatic key rotation in background
        #[cfg(feature = "p2p")]
        router.start_rotation_loop();

        router
    }

    pub fn set_cover_traffic(&self, enabled: bool) {
        self.cover_traffic_enabled
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    /// Set the relay client for server-mediated message delivery.
    #[cfg(feature = "p2p")]
    pub fn set_relay_client(&mut self, client: RelayClient) {
        self.relay_client = Some(Arc::new(client));
    }

    /// Initialize the relay client from the context's config (relay_url + proxy_url).
    #[cfg(feature = "p2p")]
    pub fn init_relay_from_config(&mut self) -> ProtocolResult<()> {
        let config = self.ctx.config();
        let client = RelayClient::new(&config.relay_url, config.proxy_url.as_deref())?;
        self.relay_client = Some(Arc::new(client));
        Ok(())
    }

    #[cfg(feature = "p2p")]
    pub fn set_p2p_node(&mut self, node: P2pNode) {
        self.p2p_node = Some(Arc::new(node));
    }

    #[cfg(feature = "p2p")]
    pub fn p2p_node(&self) -> Option<Arc<P2pNode>> {
        self.p2p_node.clone()
    }

    /// Signal the discovery loop to stop. Call before dropping the router. (FIX F-05)
    #[cfg(feature = "p2p")]
    pub fn stop_discovery(&self) {
        self.discovery_cancel.notify_waiters();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    pub async fn send_message(&self, recipient_id: &[u8], plaintext: &[u8]) -> ProtocolResult<()> {
        // FIX F-06: reject oversized payloads before any allocation
        if plaintext.len() > MAX_MESSAGE_BYTES {
            warn!(
                "SEND_REJECTED: payload {} bytes exceeds {} limit",
                plaintext.len(),
                MAX_MESSAGE_BYTES
            );
            return Err(ProtocolError::InvalidArgument);
        }

        #[cfg(feature = "p2p")]
        {
            if let Some(ref node) = self.p2p_node {
                debug!("HybridRouter: P2P node available at {}", node.local_addr());
                if let Some(peer) = self.active_peers.get(recipient_id) {
                    debug!(
                        "Using existing P2P session for {}",
                        hex::encode(recipient_id)
                    );
                    // FIX F-04: map to generic error, log details internally only
                    let res = peer.send_message(plaintext).await.map_err(|e| {
                        warn!(
                            "P2P_SEND_FAILED: recipient={} err={:?}",
                            hex::encode(recipient_id),
                            e
                        );
                        ProtocolError::InternalError
                    });
                    if res.is_ok() {
                        return Ok(());
                    }
                    warn!("P2P_FALLBACK: recipient={}", hex::encode(recipient_id));
                }
            }
        }

        #[cfg(feature = "p2p")]
        {
            self.send_via_relay(recipient_id, plaintext).await
        }

        #[cfg(not(feature = "p2p"))]
        {
            let _ = recipient_id;
            warn!("RELAY_SEND_FAILED: relay requires p2p feature");
            Err(ProtocolError::InvalidState)
        }
    }

    pub async fn send_webrtc_signal(
        &self,
        recipient_id: &[u8],
        signal: crate::media::WebRtcSignal,
    ) -> ProtocolResult<()> {
        let payload = crate::media::ProtocolPayload::WebRtc(signal);
        let bytes = payload.to_bytes()?;
        self.send_message(recipient_id, &bytes).await
    }

    pub async fn send_app_data(&self, recipient_id: &[u8], data: Vec<u8>) -> ProtocolResult<()> {
        let payload = crate::media::ProtocolPayload::Data(data);
        let bytes = payload.to_bytes()?;
        self.send_message(recipient_id, &bytes).await
    }

    // ── Discovery ─────────────────────────────────────────────────────────────

    #[cfg(feature = "p2p")]
    pub async fn start_discovery_loop(&self) -> ProtocolResult<()> {
        // FIX F-04: no internal detail in returned error
        let node = self.p2p_node.as_ref().ok_or(ProtocolError::InvalidState)?;

        let mut receiver = node.browse_peers().map_err(|e| {
            warn!("P2P_BROWSE_INIT_FAILED: {:?}", e);
            ProtocolError::InvalidState
        })?;

        let router = Arc::new(self.clone());
        let node_local = node.clone();
        let cancel = self.discovery_cancel.clone();
        let seen_sessions = std::sync::Arc::new(tokio::sync::Mutex::new(
            std::collections::HashSet::<String>::new(),
        ));

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // FIX F-05: graceful shutdown
                    _ = cancel.notified() => {
                        info!("P2P discovery loop: shutdown requested, exiting");
                        break;
                    }

                    maybe = receiver.recv() => {
                        let discovered = match maybe {
                            Some(d) => d,
                            None    => { info!("P2P discovery channel closed"); break; }
                        };

                        // FIX SIBNA-2026-029: mDNS now broadcasts a random session
                        // token, NOT the real peer ID. The real identity is only
                        // revealed after the encrypted X3DH handshake completes.
                        let session_token = &discovered.session_token;

                        // FIX F-07: validate address
                        if !is_valid_peer_addr(&discovered.addr) {
                            warn!("P2P_DISCOVERY: invalid addr {} for session {}, dropping", discovered.addr, session_token);
                            continue;
                        }

                        // FIX F-03: enforce peer cap before attempting connect
                        if router.active_peers.len() >= MAX_ACTIVE_PEERS {
                            warn!("P2P_PEER_CAP: {} peers reached, dropping session {}", MAX_ACTIVE_PEERS, session_token);
                            continue;
                        }

                        // Deduplicate by session token to avoid connecting to the
                        // same mDNS advertiser twice within one session.
                        {
                            let mut seen = seen_sessions.lock().await;
                            if !seen.insert(session_token.clone()) {
                                debug!("P2P_DISCOVERY: session {} already seen, skipping", session_token);
                                continue;
                            }
                        }

                        match node_local.connect(&discovered.addr.to_string()).await {
                            Ok(peer) => {
                                // After the handshake the real peer ID is known.
                                // Insert into active_peers keyed by the long-term identity.
                                let real_peer_id = peer.peer_id().to_vec();
                                router.active_peers
                                    .entry(real_peer_id.clone())
                                    .or_insert_with(|| {
                                        info!("P2P_CONNECTED: peer={} addr={}", hex::encode(&real_peer_id), discovered.addr);
                                        Arc::new(peer)
                                    });
                            }
                            Err(e) => {
                                // FIX F-04: log details but don't propagate them upward
                                warn!("P2P_CONNECT_FAILED: session={} addr={} err={:?}", session_token, discovered.addr, e);
                            }
                        }
                    }
                }
            }
            info!("P2P discovery loop exited");
        });

        Ok(())
    }

    #[cfg(feature = "p2p")]
    pub fn start_rotation_loop(&self) {
        let router = self.clone();
        tokio::spawn(async move {
            let interval = router.ctx.config().key_rotation_interval;
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval / 10));

            loop {
                ticker.tick().await;

                let needs_rotation;
                {
                    let keystore = router.ctx.keystore();
                    let ks = keystore.read();
                    needs_rotation =
                        !matches!(ks.get_signed_prekey(), Ok(spk) if !spk.is_expired());
                }

                if needs_rotation {
                    info!("S_ROTATION: signed prekey expired or missing, rotating...");
                    let keystore = router.ctx.keystore();
                    let mut ks = keystore.write();
                    if let Ok(new_pub) = ks.rotate_signed_prekey() {
                        info!("S_ROTATION: rotated to new SPK: {}", hex::encode(new_pub));

                        if let Some(ref _relay) = router.relay_client {
                            // Pending optimization for relay bundle upload
                        }
                    }
                }
            }
        });
    }

    // ── Relay ─────────────────────────────────────────────────────────────────

    #[cfg(feature = "p2p")]
    async fn send_via_relay(&self, recipient_id: &[u8], plaintext: &[u8]) -> ProtocolResult<()> {
        info!("RELAY_SEND: recipient={}", hex::encode(recipient_id));

        let relay = self.relay_client.as_ref().ok_or_else(|| {
            warn!("RELAY_SEND_FAILED: no relay client configured");
            ProtocolError::InvalidState
        })?;

        let ciphertext = self
            .ctx
            .encrypt_message(recipient_id, plaintext, None)
            .map_err(|e| {
                warn!("RELAY_ENCRYPT_FAILED: {:?}", e);
                ProtocolError::EncryptionFailed
            })?;

        let identity = self.ctx.get_identity().map_err(|e| {
            warn!("RELAY_IDENTITY_ERR: {:?}", e);
            ProtocolError::InternalError
        })?;

        let mut sig_env = crate::metadata::SignedEnvelope {
            recipient_id: hex::encode(recipient_id),
            payload_hex: hex::encode(ciphertext),
            sender_id: hex::encode(&identity.ed25519_public),
            timestamp: chrono::Utc::now().timestamp(),
            message_id: hex::encode(rand::thread_rng().gen::<[u8; 16]>()),
            signature_hex: String::new(),
            compressed: false,
            is_dummy: false,
        };

        let payload = sig_env.signing_payload();
        sig_env.signature_hex = hex::encode(identity.sign(&payload)?);

        let envelope_json =
            serde_json::to_string(&sig_env).map_err(|_| ProtocolError::InvalidMessage)?;

        relay.send_envelope(&envelope_json).await
    }

    // ── Peer management ───────────────────────────────────────────────────────

    /// Register a new P2P peer. Returns false if the peer cap is reached. (FIX F-03)
    #[cfg(feature = "p2p")]
    pub fn add_p2p_peer(&self, peer: Peer) -> bool {
        if self.active_peers.len() >= MAX_ACTIVE_PEERS {
            warn!(
                "P2P_PEER_CAP: cap {} reached, refusing peer {}",
                MAX_ACTIVE_PEERS,
                hex::encode(peer.peer_id())
            );
            return false;
        }
        let id = peer.peer_id().to_vec();
        info!("P2P_REGISTERED: peer={}", hex::encode(&id));
        self.active_peers.insert(id, Arc::new(peer));
        true
    }

    // ── Cover traffic ─────────────────────────────────────────────────────────

    pub fn start_cover_traffic_loop(&self, min_delay_sec: u64, max_delay_sec: u64) {
        #[cfg(not(feature = "p2p"))]
        {
            let _ = (min_delay_sec, max_delay_sec);
        }

        #[cfg(feature = "p2p")]
        {
            let router = self.clone();
            tokio::spawn(async move {
                loop {
                    if !router
                        .cover_traffic_enabled
                        .load(std::sync::atomic::Ordering::SeqCst)
                    {
                        break;
                    }

                    // FIX F-08: exponential distribution instead of uniform.
                    // Exponential inter-arrival times produce a Poisson process,
                    // which is much harder to distinguish from background traffic.
                    let delay_secs = {
                        let u: f64 = rand::thread_rng().gen_range(0.0001..=1.0);
                        let exp_delay = -f64::ln(u) * COVER_TRAFFIC_MEAN_SECS;
                        exp_delay.clamp(min_delay_sec as f64, max_delay_sec as f64) as u64
                    };
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

                    // SECURITY: pick a random dummy peer ID. Hardcoding
                    // [0u8; 32] is a fingerprint — a passive observer that sees
                    // repeated cover traffic addressed to the same all-zero
                    // recipient knows exactly which flows are dummy and can
                    // filter them out, defeating the cover-traffic guarantee.
                    let mut dummy_id = [0u8; 32];
                    {
                        let mut rng = rand::thread_rng();
                        for b in dummy_id.iter_mut() {
                            *b = rng.gen();
                        }
                    }
                    if let Err(e) = router.send_dummy_to_relay(&dummy_id) {
                        warn!("COVER_TRAFFIC_SEND_FAILED: {:?}", e);
                    }
                }
            });
        }
    }

    #[cfg(feature = "p2p")]
    #[allow(dead_code)]
    fn send_dummy_to_relay(&self, recipient_id: &[u8]) -> ProtocolResult<()> {
        debug!(
            "COVER_TRAFFIC_DUMMY: recipient={}",
            hex::encode(recipient_id)
        );

        let relay = self.relay_client.as_ref().ok_or_else(|| {
            warn!("COVER_TRAFFIC_SEND_FAILED: no relay client configured");
            ProtocolError::InvalidState
        })?;

        let mut junk = vec![0u8; 64];
        rand::thread_rng().fill(&mut junk[..]);

        let ciphertext = self.ctx.encrypt_message(recipient_id, &junk, None)?;

        let identity = self.ctx.get_identity().map_err(|e| {
            warn!("COVER_TRAFFIC_IDENTITY_ERR: {:?}", e);
            ProtocolError::InternalError
        })?;

        // VERIFIED: is_dummy IS included in signing_payload() — see metadata.rs
        // line 121: `hasher.update(&[self.is_dummy as u8])`.
        // Original audit finding #3 was a false positive.
        let mut sig_env = crate::metadata::SignedEnvelope {
            recipient_id: hex::encode(recipient_id),
            payload_hex: hex::encode(ciphertext),
            sender_id: hex::encode(&identity.ed25519_public),
            timestamp: chrono::Utc::now().timestamp(),
            message_id: hex::encode(rand::thread_rng().gen::<[u8; 16]>()),
            signature_hex: String::new(),
            compressed: false,
            is_dummy: true, // ← hashed into signing_payload
        };

        let payload = sig_env.signing_payload();
        sig_env.signature_hex = hex::encode(identity.sign(&payload)?);

        let envelope_json =
            serde_json::to_string(&sig_env).map_err(|_| ProtocolError::InvalidMessage)?;

        // Use tokio::spawn for async send from sync context
        let relay_clone = relay.clone();
        let json_clone = envelope_json;
        tokio::spawn(async move {
            if let Err(e) = relay_clone.send_envelope(&json_clone).await {
                warn!("COVER_TRAFFIC_SEND_FAILED: {:?}", e);
            }
        });

        Ok(())
    }
}

// ── Address validation ────────────────────────────────────────────────────────

/// Returns true only for addresses safe to dial. (FIX F-07)
#[cfg(feature = "p2p")]
fn is_valid_peer_addr(addr: &std::net::SocketAddr) -> bool {
    let ip = addr.ip();
    // Reject unroutable / control addresses
    if ip.is_loopback() {
        return false;
    } // 127.x / ::1
    if ip.is_multicast() {
        return false;
    } // 224.x / ff00::/8
    if ip.is_unspecified() {
        return false;
    } // 0.0.0.0 / ::
    if addr.port() == 0 {
        return false;
    } // unassigned port
    true
    // NOTE: RFC-1918 private addresses are intentionally allowed — mDNS
    // discovery is LAN-scoped by design. Revisit if the discovery layer
    // ever extends to public networks.
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[cfg(feature = "p2p")]
    use super::is_valid_peer_addr;

    #[cfg(feature = "p2p")]
    #[test]
    fn rejects_loopback() {
        assert!(!is_valid_peer_addr(&"127.0.0.1:4000".parse().unwrap()));
        assert!(!is_valid_peer_addr(&"[::1]:4000".parse().unwrap()));
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn rejects_unspecified() {
        assert!(!is_valid_peer_addr(&"0.0.0.0:4000".parse().unwrap()));
        assert!(!is_valid_peer_addr(&"[::]:4000".parse().unwrap()));
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn rejects_zero_port() {
        assert!(!is_valid_peer_addr(&"192.168.1.5:0".parse().unwrap()));
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn allows_lan_address() {
        assert!(is_valid_peer_addr(&"192.168.1.100:4000".parse().unwrap()));
        assert!(is_valid_peer_addr(&"10.0.0.5:9000".parse().unwrap()));
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn allows_public_address() {
        assert!(is_valid_peer_addr(&"203.0.113.5:4000".parse().unwrap()));
    }
}
