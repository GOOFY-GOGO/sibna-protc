# Sibna Protocol Go SDK

Go implementation of the Sibna Protocol for ultra-secure messaging.

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

- Go 1.21+

## Installation

```bash
go get github.com/SibnaOfficial/sibna-protc/sdks/go
```

## Usage

```go
package main

import (
    "fmt"
    sibna "github.com/SibnaOfficial/sibna-protc/sdks/go"
)

func main() {
    // Create client
    client := sibna.NewClient("https://sibna.example.com", nil)

    // Generate identity
    identity, _ := sibna.GenerateIdentity()

    // Authenticate
    token, _ := client.Authenticate(identity)

    // Send encrypted message
    client.SendMessage(recipientId, plaintext, token)
}
```

## Security

- All keys are zeroized on destruction
- Constant-time comparisons for signatures
- TLS 1.3 with certificate pinning
- Forward secrecy via Double Ratchet
