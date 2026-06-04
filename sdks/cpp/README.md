# Sibna Protocol C++ SDK

C++ implementation of the Sibna Protocol for ultra-secure messaging.

## Features

- Ed25519/X25519 identity key generation
- X3DH handshake for session establishment
- Double Ratchet for forward secrecy
- ChaCha20-Poly1305 authenticated encryption
- Group messaging with sender keys
- Safety numbers for identity verification
- TLS certificate pinning

## Requirements

- C++17 or later
- OpenSSL 3.x
- CMake 3.14+

## Building

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Usage

```cpp
#include <sibna/sibna.h>

// Create context
auto context = sibna::Context::create().value();

// Generate identity
auto identity = context->generate_identity().value();

// Create session with peer
auto session = context->create_session(peer_id).value();

// Encrypt message
auto ciphertext = session->encrypt(plaintext).value();

// Decrypt message
auto plaintext = session->decrypt(ciphertext).value();
```

## Security

- All keys are zeroized on destruction
- Constant-time comparisons for signatures
- TLS 1.3 with certificate pinning
- Forward secrecy via Double Ratchet
