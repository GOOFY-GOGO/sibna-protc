use sibna_core::crypto::padding::{pad_message, PaddingMode};

fn main() {
    let msg1 = b"Short message";
    let msg2 = vec![0x42u8; 10000]; // 10KB message
    
    let padded1 = pad_message(msg1, PaddingMode::Quantum).unwrap();
    let padded2 = pad_message(&msg2, PaddingMode::Quantum).unwrap();
    
    println!("Message 1 (13B) Padded Size: {} bytes", padded1.len());
    println!("Message 2 (10KB) Padded Size: {} bytes", padded2.len());
    
    assert_eq!(padded1.len(), 65536);
    assert_eq!(padded2.len(), 65536);
    println!("✅ Quantum Padding Verified: All messages are exactly 64KB.");
}
