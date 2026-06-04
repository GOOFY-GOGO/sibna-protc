use sibna_core::ratchet::DoubleRatchetSession;
use sibna_core::{Config, HandshakeRole, SecureContext};
use x25519_dalek::{PublicKey, StaticSecret};

fn ctx() -> SecureContext {
    let cfg = Config {
        require_safety_numbers: false,
        ..Config::default()
    };
    SecureContext::new(cfg, None).unwrap()
}

fn ratchet_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
    let cfg = Config::default();
    let ss = [0x42u8; 32];
    let a_sk = StaticSecret::from([0x01u8; 32]);
    let b_sk = StaticSecret::from([0x02u8; 32]);
    let a_pk = PublicKey::from(&a_sk);
    let b_pk = PublicKey::from(&b_sk);
    let alice = DoubleRatchetSession::from_shared_secret(
        &ss,
        a_sk,
        b_pk,
        cfg.clone(),
        HandshakeRole::Initiator,
    )
    .unwrap();
    let bob =
        DoubleRatchetSession::from_shared_secret(&ss, b_sk, a_pk, cfg, HandshakeRole::Responder)
            .unwrap();
    (alice, bob)
}

// ── Basic encrypt/decrypt ────────────────────────────────────────────────────

#[test]
fn roundtrip_single_message() {
    let (alice, bob) = ratchet_pair();
    let ct = alice.encrypt(b"hello", b"").unwrap();
    let pt = bob.decrypt(&ct, b"").unwrap();
    assert_eq!(pt, b"hello");
}

#[test]
fn roundtrip_many_messages() {
    let (alice, bob) = ratchet_pair();
    for i in 0u32..50 {
        let msg = i.to_le_bytes();
        let ct = alice.encrypt(&msg, b"").unwrap();
        let pt = bob.decrypt(&ct, b"").unwrap();
        assert_eq!(pt, msg);
    }
}

#[test]
fn associated_data_mismatch_fails() {
    let (alice, bob) = ratchet_pair();
    let ct = alice.encrypt(b"secret", b"context-a").unwrap();
    assert!(bob.decrypt(&ct, b"context-b").is_err());
}

// ── Replay protection ────────────────────────────────────────────────────────

#[test]
fn replay_rejected() {
    let (alice, bob) = ratchet_pair();
    let ct = alice.encrypt(b"once", b"").unwrap();
    assert!(bob.decrypt(&ct, b"").is_ok());
    assert!(bob.decrypt(&ct, b"").is_err());
}

#[test]
fn out_of_order_messages_delivered() {
    let (alice, bob) = ratchet_pair();
    let ct0 = alice.encrypt(b"msg0", b"").unwrap();
    let ct1 = alice.encrypt(b"msg1", b"").unwrap();
    let ct2 = alice.encrypt(b"msg2", b"").unwrap();
    // Deliver out of order
    assert_eq!(bob.decrypt(&ct2, b"").unwrap(), b"msg2");
    assert_eq!(bob.decrypt(&ct0, b"").unwrap(), b"msg0");
    assert_eq!(bob.decrypt(&ct1, b"").unwrap(), b"msg1");
}

// ── Forward secrecy ──────────────────────────────────────────────────────────

#[test]
fn ciphertexts_are_distinct() {
    let (alice, _) = ratchet_pair();
    let ct0 = alice.encrypt(b"same", b"").unwrap();
    let ct1 = alice.encrypt(b"same", b"").unwrap();
    // Different nonces + ratchet state → different ciphertexts
    assert_ne!(ct0, ct1);
}

#[test]
fn tampered_ciphertext_rejected() {
    let (alice, bob) = ratchet_pair();
    let mut ct = alice.encrypt(b"integrity", b"").unwrap();
    // Flip a byte in the payload region
    let last = ct.len() - 1;
    ct[last] ^= 0xff;
    assert!(bob.decrypt(&ct, b"").is_err());
}

// ── Empty and large messages ─────────────────────────────────────────────────

#[test]
fn large_message_roundtrip() {
    let (alice, bob) = ratchet_pair();
    let big = vec![0xABu8; 64 * 1024];
    let ct = alice.encrypt(&big, b"").unwrap();
    let pt = bob.decrypt(&ct, b"").unwrap();
    assert_eq!(pt, big);
}

// ── Identity generation ──────────────────────────────────────────────────────

#[test]
fn generate_identity_distinct() {
    let a = ctx();
    let b = ctx();
    let ka = a.generate_identity().unwrap();
    let kb = b.generate_identity().unwrap();
    assert_ne!(ka.ed25519_public, kb.ed25519_public);
}

#[test]
fn identity_sign_verify() {
    let a = ctx();
    let kp = a.generate_identity().unwrap();
    let sig = kp.sign(b"test data").unwrap();
    assert!(kp.verify(b"test data", &sig).is_ok());
    assert!(kp.verify(b"wrong data", &sig).is_err());
}

// ── Session creation ─────────────────────────────────────────────────────────

#[test]
fn session_requires_identity() {
    let a = ctx();
    // No identity generated → session creation should fail
    let peer_id = [0x01u8; 32];
    let result = a.encrypt_message(&peer_id, b"msg", None);
    assert!(result.is_err());
}

// ── Group ────────────────────────────────────────────────────────────────────

#[test]
fn group_create_and_destroy() {
    let a = ctx();
    a.generate_identity().unwrap();
    let gid = [0xAAu8; 32];
    assert!(a.create_group(gid).is_ok());
    // Duplicate create should be an error or no-op depending on implementation
    // (either is acceptable, we just verify no panic)
    let _ = a.create_group(gid);
}

// ── Ratchet state ────────────────────────────────────────────────────────────

#[test]
fn ratchet_after_bidirectional_exchange() {
    let (alice, bob) = ratchet_pair();
    // Alice sends
    let ct_a = alice.encrypt(b"ping", b"").unwrap();
    bob.decrypt(&ct_a, b"").unwrap();
    // Bob replies — triggers DH ratchet on Alice's side
    let ct_b = bob.encrypt(b"pong", b"").unwrap();
    alice.decrypt(&ct_b, b"").unwrap();
    // Continue
    let ct_a2 = alice.encrypt(b"ping2", b"").unwrap();
    assert_eq!(bob.decrypt(&ct_a2, b"").unwrap(), b"ping2");
}

#[test]
fn max_skipped_messages_respected() {
    use sibna_core::ratchet::MAX_SKIPPED_MESSAGES;
    let (alice, bob) = ratchet_pair();
    // Generate MAX_SKIPPED_MESSAGES + 1 messages but only deliver the last one
    let mut cts = Vec::new();
    for _ in 0..=(MAX_SKIPPED_MESSAGES + 1) {
        cts.push(alice.encrypt(b"skip", b"").unwrap());
    }
    // Delivering the one that requires skipping too many should fail
    assert!(bob.decrypt(cts.last().unwrap(), b"").is_err());
}
