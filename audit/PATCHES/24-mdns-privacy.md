# PATCH 24 — Replace static mDNS peer ID with random session token

**Finding:** SIBNA-2026-029
**Severity:** MEDIUM (privacy)
**Date:** 2026-06-03

## Problem

The mDNS service advertised the node's full 32-byte Ed25519 identity key
as a `peer_id` TXT property in cleartext. Any device on the same local
network could:

1. Passively collect stable peer identifiers via mDNS
2. Track device movement across network segments
3. Correlate mDNS presence with network traffic
4. Build a mapping of Ed25519 keys to physical devices

The `peer_id` was static — it never changed between restarts — making it
a reliable tracking identifier.

## Solution

Replace the static `peer_id` with a random 16-byte (128-bit) session
token regenerated on every restart. The real peer identity is only
revealed after the encrypted X3DH handshake completes.

### Changes

**`core/src/p2p/discovery.rs`:**

- Removed `peer_id_bytes: &[u8; 32]` parameter from `MdnsDiscovery::new()`
- Added `rand::RngCore` import for random token generation
- Generate random 16-byte `token_bytes` using `rand::thread_rng().fill_bytes()`
- mDNS instance name now uses first 12 hex chars of the session token
  (not the real peer ID)
- TXT property changed from `peer_id` → `session` containing the random token
- Version bumped from `"1"` → `"2"` (mDNS protocol version)
- `DiscoveredPeer` struct: renamed `peer_id_hex` → `session_token`
- Updated `browse_peers()` to read `session` property instead of `peer_id`

**`core/src/p2p/node.rs`:**

- Updated `MdnsDiscovery::new()` call to remove `&identity.ed25519_public`
  parameter

**`core/src/manager.rs`:**

- Added `seen_sessions: Arc<Mutex<HashSet<String>>>` to track already-seen
  mDNS session tokens (deduplication during discovery phase)
- Removed hex validation of `peer_id_hex` (no longer needed — it's a random
  token, not an identity key)
- After successful `connect()`, the real peer ID is obtained from
  `peer.peer_id()` and used as the DashMap key

## Privacy Guarantee

| Phase | Identifier visible | Who sees it |
|-------|-------------------|-------------|
| mDNS broadcast | Random 16-byte session token | Anyone on LAN |
| After X3DH handshake | Real 32-byte Ed25519 identity | Both peers only |

An attacker on the LAN can observe:
- A random token that changes every restart → **no cross-session tracking**
- The IP address and port → same as any TCP connection

An attacker **cannot** observe:
- The real Ed25519 identity key
- Any linkable identifier across restarts

## Verification

- `cargo check --workspace` — clean (0 errors)
- `cargo test --lib -p sibna-core` — 145/145 passed
- `cargo test --test integration -p sibna-core -- --skip mdns` — 14/14 passed
- `cargo test --test attack_tests -p sibna-tests` — 1/1 passed

## Residual Risk

- mDNS still uses UDP multicast (unencrypted) — acceptable for LAN-only
  service discovery. The session token provides no identity information.
- If the attacker can correlate IP addresses across restarts (DHCP lease
  persistence), they could theoretically track devices. This is a network-
  layer issue outside the scope of this protocol.

## Backward Compatibility

- mDNS protocol version bumped from `"1"` to `"2"` — old nodes will not
  recognize the new `session` property. This is acceptable for a major
  version bump (v3.0.0).
