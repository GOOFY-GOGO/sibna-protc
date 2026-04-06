use sibna_core::{Config, SecureContext, ProtocolError};
use x25519_dalek::{StaticSecret, PublicKey};

/// Initialize a strict context bypassing Tor/P2P overlays
fn setup_core_context() -> SecureContext {
    SecureContext::new(Config::core_mode(), None).unwrap()
}

#[tokio::test]
async fn test_offensive_require_safety_numbers_enforcement() {
    let alice = setup_core_context();
    let bob = setup_core_context();

    let _ = alice.generate_identity().unwrap();
    let bob_id = bob.generate_identity().unwrap();

    let peer_id = bob_id.ed25519_public;

    // ATTACK: Alice tries to send a message to Bob without verifying his identity.
    let result = alice.create_session(&peer_id);
    
    assert!(
        matches!(result, Err(ProtocolError::VerificationRequired)),
        "Strict verification failed: Protocol allowed TOFU session creation!"
    );

    // DEFENSE: Alice successfully verifies Bob's Safety Number out-of-band.
    let keystore_arc = alice.keystore();
    let mut alice_keystore = keystore_arc.write();
    assert!(alice_keystore.verify_or_pin_peer_key(&peer_id, &peer_id).is_ok());
    alice_keystore.mark_peer_verified(&peer_id);
    drop(alice_keystore);

    let session_result = alice.create_session(&peer_id);
    assert!(session_result.is_ok(), "Session creation failed even after verification!");
}

#[tokio::test]
async fn test_offensive_replay_attack_mitigation() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    // Symmetric setup for raw ratchet test
    let shared_secret = [0x5A; 32];
    let alice_secret = StaticSecret::from([0x4A; 32]);
    let bob_secret = StaticSecret::from([0x4B; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice_session = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob_session = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    let plaintext = b"SECRET_STRIKE";
    let ciphertext1 = alice_session.encrypt(plaintext, b"").unwrap();
    
    let decrypted1 = bob_session.decrypt(&ciphertext1, b"").unwrap();
    assert_eq!(decrypted1, plaintext);

    // ATTACK: Eve intercepts `ciphertext1` and replays it to Bob later.
    let replay_result = bob_session.decrypt(&ciphertext1, b"");
    assert!(
        matches!(replay_result, Err(ProtocolError::ReplayAttackDetected)),
        "Ratchet failed to detect Replay Attack!"
    );
}

#[tokio::test]
async fn test_offensive_forged_envelope_rejection() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let shared_secret = [0x99; 32];
    let alice_secret = StaticSecret::from([0x1A; 32]);
    let bob_secret = StaticSecret::from([0x1B; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice_session = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let plaintext = b"HONEST_MESSAGE";
    let mut ciphertext = alice_session.encrypt(plaintext, b"").unwrap();

    // ATTACK: Eve flips a single bit in the ciphertext data.
    // RatchetMessage: Header(56) + Nonce(12) + Payload(N) + Tag(16)
    // Index 70 should be in the payload area.
    if ciphertext.len() > 70 {
        ciphertext[70] ^= 0x01;
    }

    let bob_session = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    let forgery_result = bob_session.decrypt(&ciphertext, b"");
    // Should fail with Auth failure (represented by DecryptionFailed/AuthenticationFailed in Core)
    assert!(
        forgery_result.is_err(),
        "Forged encrypted packet bypassed MAC verification!"
    );
}

#[tokio::test]
async fn test_offensive_session_desync_handling() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let shared_secret = [0xEE; 32];
    let alice_secret = StaticSecret::from([0x11; 32]);
    let bob_secret = StaticSecret::from([0x22; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true
    ).unwrap();

    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config.clone(), false
    ).unwrap();

    let mut messages = Vec::new();
    for i in 0..5 {
        messages.push(alice.encrypt(format!("MSG_{}", i).as_bytes(), b"").unwrap());
    }

    let order = [4, 0, 2, 1, 3];
    for &idx in &order {
        let dec = bob.decrypt(&messages[idx], b"").unwrap();
        assert_eq!(dec, format!("MSG_{}", idx).as_bytes());
    }

    let msg6 = alice.encrypt(b"MSG_SYNC", b"").unwrap();
    let dec6 = bob.decrypt(&msg6, b"").unwrap();
    assert_eq!(dec6, b"MSG_SYNC");
}

#[tokio::test]
async fn test_offensive_identity_swap_detection() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let alice = SecureContext::new(config.clone(), None).unwrap();
    let bob = SecureContext::new(config.clone(), None).unwrap();

    let _ = alice.generate_identity().unwrap();
    let bob_id = bob.generate_identity().unwrap();

    let keystore_arc = alice.keystore();
    let mut alice_ks = keystore_arc.write();
    alice_ks.verify_or_pin_peer_key(b"bob_user", &bob_id.ed25519_public).unwrap();
    drop(alice_ks);

    let eve_id = [0xCC; 32]; 
    let mut alice_ks = keystore_arc.write();
    let result = alice_ks.verify_or_pin_peer_key(b"bob_user", &eve_id);
    
    assert!(
        matches!(result, Err(ProtocolError::KeyMismatch)),
        "Identity swap attack went undetected!"
    );
}

#[tokio::test]
async fn test_offensive_state_persistence_integrity() {
    let mut config = Config::default();
    config.require_safety_numbers = false;

    let shared_secret = [0x77; 32];
    let alice_secret = StaticSecret::from([0x33; 32]);
    let bob_secret = StaticSecret::from([0x44; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true
    ).unwrap();

    let _ = alice.encrypt(b"PERSIST_TEST_1", b"").unwrap();
    let (s1, _) = alice.message_stats();
    assert_eq!(s1, 1);

    let state_bytes = alice.serialize_state().unwrap();
    
    let alice_restored = sibna_core::ratchet::DoubleRatchetSession::new(config.clone()).unwrap();
    alice_restored.deserialize_state(&state_bytes).unwrap();
    
    let ciphertext2 = alice_restored.encrypt(b"PERSIST_TEST_2", b"").unwrap();
    
    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config.clone(), false
    ).unwrap();
    
    let dec2 = bob.decrypt(&ciphertext2, b"").unwrap();
    assert_eq!(dec2, b"PERSIST_TEST_2");
    
    let (s_num, _) = alice_restored.message_stats();
    assert_eq!(s_num, 2, "Message counter was not restored properly!");
}

#[tokio::test]
async fn test_offensive_pq_downgrade_prevention() {
    let config = Config::core_mode(); 


    let alice = SecureContext::new(config.clone(), None).unwrap();
    let bob = SecureContext::new(config.clone(), None).unwrap();

    let _ = alice.generate_identity().unwrap();
    let _ = bob.generate_identity().unwrap(); // Bob needs identity
    bob.generate_signed_prekey().unwrap(); // Bob needs signed prekey
    
    let bob_id = bob.get_identity_public().unwrap();
    let bob_bundle = bob.keystore().read().get_signed_prekey_public().unwrap();

    // ATTACK: Eve strips the PQ components from the handshake.
    let result = alice.perform_handshake(
        b"bob",
        true,
        Some(&bob_id),
        Some(&bob_bundle),
        None, 
        None,
    );

    #[cfg(feature = "pqc")]
    {
        assert!(
            result.is_err(), 
            "Handshake allowed classical downgrade in Core Mode despite PQC feature!"
        );
    }
}

#[tokio::test]
async fn test_concurrent_replay_race_condition() {
    use std::sync::Arc;
    use tokio::sync::Barrier;

    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let shared_secret = [0xBB; 32];
    let alice_secret = StaticSecret::from([0xAA; 32]);
    let bob_secret = StaticSecret::from([0xBB; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob = Arc::new(tokio::sync::RwLock::new(
        sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
            &shared_secret, bob_secret, alice_pub, config, false,
        ).unwrap()
    ));

    let plaintext = b"RACE_MESSAGE";
    let ciphertext = alice.encrypt(plaintext, b"").unwrap();

    let num_attackers = 50;
    let barrier = Arc::new(Barrier::new(num_attackers));
    let mut handlers = Vec::new();

    for _ in 0..num_attackers {
        let b = barrier.clone();
        let bob_clone = bob.clone();
        let ct_clone = ciphertext.clone();
        
        handlers.push(tokio::spawn(async move {
            b.wait().await; // Synchronize attackers to strike at the same instant
            let bob_guard = bob_clone.write().await;
            bob_guard.decrypt(&ct_clone, b"")
        }));
    }

    let mut success_count = 0;
    let mut replay_detected_count = 0;

    for h in handlers {
        match h.await.unwrap() {
            Ok(_) => success_count += 1,
            Err(ProtocolError::ReplayAttackDetected) => replay_detected_count += 1,
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    assert_eq!(success_count, 1, "Exactly one decryption should succeed; found {}", success_count);
    assert_eq!(replay_detected_count, num_attackers - 1, "All other attempts must be detected as replays");
}

#[tokio::test]
async fn test_resource_exhaustion_skipped_keys_bomb() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    config.max_skipped_messages = 50; // Set low for test
    
    let shared_secret = [0x77; 32];
    let alice_secret = StaticSecret::from([0x11; 32]);
    let bob_secret = StaticSecret::from([0x22; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    // ATTACK: Alice sends message #100, skipping 99 messages.
    // Our max_skip is 50.
    let mut large_jump_ct = Vec::new();
    for _ in 0..60 {
        large_jump_ct = alice.encrypt(b"BOMB", b"").unwrap();
    }

    let result = bob.decrypt(&large_jump_ct, b"");
    assert!(
        matches!(result, Err(ProtocolError::MaxSkippedMessagesExceeded)),
        "Ratchet failed to prevent resource exhaustion (skipped keys bomb)!"
    );
}

#[tokio::test]
async fn test_fuzz_active_tampering_resilience() {
    use rand::Rng;

    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let shared_secret = [0x55; 32];
    let alice_secret = StaticSecret::from([0x33; 32]);
    let bob_secret = StaticSecret::from([0x44; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    let mut rng = rand::thread_rng();

    for i in 0..20 {
        let plaintext = format!("MSG_{}", i);
        let mut ct = alice.encrypt(plaintext.as_bytes(), b"").unwrap();

        // ATTACK: Flip a random byte in the total ciphertext/tag region
        // We start from 56 (after RatchetHeader) to test both EncryptorHeader and Payload/Tag
        let flip_idx = rng.gen_range(56..ct.len());
        ct[flip_idx] ^= 0xFF;

        let result = bob.decrypt(&ct, b"");
        assert!(result.is_err(), "Tampered ciphertext #{} was accepted! (Index: {}, Size: {})", i, flip_idx, ct.len());
        
        // HEARTBEAT: Ensure the ratchet is NOT stuck/corrupted after tampering.
        let valid_ct = alice.encrypt(b"HEARTBEAT", b"").unwrap();
        let valid_dec = bob.decrypt(&valid_ct, b"").unwrap();
        assert_eq!(valid_dec, b"HEARTBEAT", "Session state corrupted by malformed input!");
    }
}

#[tokio::test]
async fn test_high_latency_extreme_reordering() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let shared_secret = [0x33; 32];
    let alice_secret = StaticSecret::from([0x1A; 32]);
    let bob_secret = StaticSecret::from([0x2B; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    let mut messages = Vec::new();
    for i in 0..20 {
        messages.push(alice.encrypt(format!("REORDER_{}", i).as_bytes(), b"").unwrap());
    }

    // Extreme reordering: decrypt in reverse, then skip some, then fill gaps
    let indices = [19, 18, 0, 1, 10, 5, 6, 7, 8, 9, 2, 3, 4, 11, 12, 13, 14, 15, 16, 17];
    
    for &idx in &indices {
        let dec = bob.decrypt(&messages[idx], b"").unwrap();
        assert_eq!(dec, format!("REORDER_{}", idx).as_bytes());
    }
}

#[tokio::test]
async fn test_offensive_timestamp_time_travel() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let shared_secret = [0x12; 32];
    let alice_secret = StaticSecret::from([0x22; 32]);
    let bob_secret = StaticSecret::from([0x33; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    // ATTACK: Eve modifies the timestamp to 10 years in the future (bypass expiry logic)
    let mut ct = alice.encrypt(b"FUTURE_MSG", b"").unwrap();
    
    // Header timestamp is at index 48-55 in RatchetHeader
    let future_ts = 2147483647u64; // Far future
    let ts_bytes = future_ts.to_le_bytes();
    ct[48..56].copy_from_slice(&ts_bytes);

    let result = bob.decrypt(&ct, b"");
    assert!(result.is_err(), "Protocol accepted a message from the far future!");
}

#[tokio::test]
async fn test_offensive_header_dh_corruption() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let shared_secret = [0x90; 32];
    let alice_secret = StaticSecret::from([0x11; 32]);
    let bob_secret = StaticSecret::from([0x22; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    let mut ct = alice.encrypt(b"DH_TAMPER", b"").unwrap();
    
    // ATTACK: Flip a bit in the RatchetHeader DH public key (bytes 0-31)
    ct[5] ^= 0x01;

    let result = bob.decrypt(&ct, b"");
    assert!(result.is_err(), "Tampered DH public key in header bypassed authentication!");
}

#[tokio::test]
async fn test_offensive_chain_inflation_dos() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    config.max_skipped_messages = 5000;
    
    let shared_secret = [0xDD; 32];
    let alice_secret = StaticSecret::from([0x1A; 32]);
    let bob_secret = StaticSecret::from([0x2B; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    let payload = b"STEP";
    let mut messages = Vec::new();
    for _ in 0..90 {
        messages.push(alice.encrypt(payload, b"").unwrap());
    }

    let dec = bob.decrypt(&messages[89], b"").unwrap();
    assert_eq!(dec, payload);

    // After a DH step, the limit should reset
    let reply = bob.encrypt(b"DH Update", b"").unwrap();
    alice.decrypt(&reply, b"").unwrap();
    
    // Alice can now send another 90
    for _ in 0..90 {
        alice.encrypt(payload, b"").unwrap();
    }
}

#[tokio::test]
async fn test_offensive_large_payload_stress() {
    let mut config = Config::default();
    config.require_safety_numbers = false;
    
    let shared_secret = [0xFA; 32];
    let alice_secret = StaticSecret::from([0xAA; 32]);
    let bob_secret = StaticSecret::from([0xBB; 32]);
    let alice_pub = PublicKey::from(&alice_secret);
    let bob_pub = PublicKey::from(&bob_secret);

    let alice = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, alice_secret, bob_pub, config.clone(), true,
    ).unwrap();

    let bob = sibna_core::ratchet::DoubleRatchetSession::from_shared_secret(
        &shared_secret, bob_secret, alice_pub, config, false,
    ).unwrap();

    let large_data = vec![0xEEu8; 1024 * 1024];
    let ct = alice.encrypt(&large_data, b"").unwrap();
    
    let dec = bob.decrypt(&ct, b"").unwrap();
    assert_eq!(dec.len(), large_data.len());
    assert_eq!(dec[500], 0xEE);
}
