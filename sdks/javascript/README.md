# Sibna Protocol JavaScript/TypeScript SDK

JavaScript/TypeScript implementation of the Sibna Protocol for ultra-secure messaging.

## Features

- Ed25519/X25519 identity key generation
- X3DH handshake for session establishment
- Double Ratchet for forward secrecy
- ChaCha20-Poly1305 authenticated encryption
- Group messaging with sender keys
- Safety numbers for identity verification
- HTTP and WebSocket transports
- TLS certificate pinning

## Requirements

- Node.js 18+ or modern browser
- Optional: `@noble/ed25519` for Ed25519 operations

## Installation

```bash
npm install sibna-protocol
```

## Usage

```typescript
import { SibnaClient, SibnaContext } from 'sibna-protocol';

// Create context
const context = await SibnaContext.create();

// Generate identity
const identity = await context.generateIdentity();

// Create client
const client = new SibnaClient('https://sibna.example.com');

// Authenticate
const token = await client.authenticate(identity);

// Send encrypted message
await client.sendMessage(recipientId, plaintext);
```

## Security

- All keys are zeroized on destruction
- Constant-time comparisons for signatures
- TLS 1.3 with certificate pinning
- Forward secrecy via Double Ratchet
