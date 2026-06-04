# Sibna Protocol Dart SDK

Dart implementation of the Sibna Protocol for ultra-secure messaging.

## Features

- Ed25519/X25519 identity key generation (via FFI)
- X3DH handshake for session establishment
- Double Ratchet for forward secrecy
- ChaCha20-Poly1305 authenticated encryption
- Group messaging with sender keys
- Safety numbers for identity verification
- FFI bindings to native library

## Requirements

- Dart 3.0+
- Native library (libsibna.so/dll/dylib)

## Installation

```yaml
dependencies:
  sibna_protocol:
    path: sdks/dart
```

## Usage

```dart
import 'package:sibna_protocol/sibna_protocol.dart';

// Initialize SDK
await SibnaProtocol.initialize();

// Create context
final context = await SibnaContext.create();

// Create session
final session = await context.createSession(peerId);

// Encrypt message
final ciphertext = await session.encrypt(plaintext);

// Decrypt message
final plaintext = await session.decrypt(ciphertext);
```

## Security

- All keys are zeroized on destruction
- Constant-time comparisons for signatures
- Forward secrecy via Double Ratchet
