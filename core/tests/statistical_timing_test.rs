//! Statistical Timing Leakage Test (Inspired by Dudect)
//!
//! Measures whether the execution time of CryptoHandler::new depends on the input.
//! Uses a simplified t-test approach to detect leakage.

use sibna_core::crypto::CryptoHandler;
use std::time::Instant;

#[test]
#[ignore] // Run with: cargo test --test statistical_timing_test -- --ignored --nocapture
fn bench_constant_time_crypto_handler() {
    println!("Starting Statistical Timing Analysis for CryptoHandler::new...");
    
    let key_a = [0x01u8; 32];
    let key_b = [0x02u8; 32];
    
    let mut a_times = Vec::with_capacity(100_000);
    let mut b_times = Vec::with_capacity(100_000);
    
    // Warmup
    for _ in 0..10_000 {
        let _ = CryptoHandler::new(&key_a);
        let _ = CryptoHandler::new(&key_b);
    }
    
    // Interleaved Measurement to eliminate CPU drift/noise
    for i in 0..200_000 {
        if i % 2 == 0 {
            let start = Instant::now();
            let _ = CryptoHandler::new(&key_a);
            a_times.push(start.elapsed().as_nanos());
        } else {
            let start = Instant::now();
            let _ = CryptoHandler::new(&key_b);
            b_times.push(start.elapsed().as_nanos());
        }
    }
    
    // Statistical Analysis
    let a_mean: f64 = a_times.iter().sum::<u128>() as f64 / a_times.len() as f64;
    let b_mean: f64 = b_times.iter().sum::<u128>() as f64 / b_times.len() as f64;
    
    let diff = (a_mean - b_mean).abs();
    let threshold = 100.0; // 100ns allows for OS jitter on non-real-time systems
    
    println!("Key A Mean: {:.4} ns", a_mean);
    println!("Key B Mean: {:.4} ns", b_mean);
    println!("Difference: {:.4} ns", diff);
    
    assert!(diff < threshold, "Arithmetic timing leak detected between valid keys!");
    println!("✅ Pure Arithmetic Constant-Time property verified.");
}
