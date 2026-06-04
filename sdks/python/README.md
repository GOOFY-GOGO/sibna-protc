# Sibna Protocol Python SDK

Python implementation of the Sibna Protocol for ultra-secure messaging.

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

- Python 3.8+
- Optional: `cryptography`, `requests`, `aiohttp`, `websockets`

## Installation

```bash
pip install sibna-protocol
```

## Usage

```python
from sibna import SibnaContext, SibnaClient

# Create context
context = SibnaContext.create()

# Generate identity
identity = context.generate_identity()

# Create client
client = SibnaClient("https://sibna.example.com")

# Authenticate
token = client.authenticate(identity)

# Send encrypted message
client.send_message(recipient_id, plaintext)
```

## Security

- All keys are zeroized on destruction
- Constant-time comparisons for signatures
- TLS 1.3 with certificate pinning
- Forward secrecy via Double Ratchet
