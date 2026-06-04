# Sibna Protocol Java SDK

Java implementation of the Sibna Protocol for ultra-secure messaging.

## Features

- Ed25519/X25519 identity key generation
- X3DH handshake for session establishment
- Double Ratchet for forward secrecy
- ChaCha20-Poly1305 authenticated encryption
- Group messaging with sender keys
- Safety numbers for identity verification
- HTTP transport with TLS certificate pinning

## Requirements

- Java 17+
- Maven

## Installation

```xml
<dependency>
    <groupId>com.sibna</groupId>
    <artifactId>sibna-protocol</artifactId>
    <version>3.0.0</version>
</dependency>
```

## Usage

```java
import com.sibna.SibnaClient;
import com.sibna.identity.IdentityKeyPair;

// Create client
SibnaClient client = new SibnaClient("https://sibna.example.com");

// Generate identity
IdentityKeyPair identity = client.generateIdentity();

// Authenticate
String token = client.authenticate();

// Send encrypted message
client.sendMessage(recipientId, ciphertext);
```

## Security

- All keys are zeroized on destruction
- Constant-time comparisons for signatures
- TLS 1.3 with certificate pinning
- Forward secrecy via Double Ratchet
