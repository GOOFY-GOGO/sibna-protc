// Package sibna provides the Go SDK for the Sibna Protocol v3.0.0.
package sibna

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	if len(identity.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(identity.PublicKey), ed25519.PublicKeySize)
	}
	if len(identity.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(identity.PrivateKey), ed25519.PrivateKeySize)
	}
}

func TestIdentityFromSeed(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	identity, err := IdentityFromSeed(seed)
	if err != nil {
		t.Fatalf("IdentityFromSeed failed: %v", err)
	}
	if len(identity.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(identity.PublicKey), ed25519.PublicKeySize)
	}
}

func TestIdentityFromSeedInvalidLength(t *testing.T) {
	_, err := IdentityFromSeed(make([]byte, 16))
	if err == nil {
		t.Error("expected error for invalid seed length")
	}
}

func TestPublicKeyHex(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	hexStr := identity.PublicKeyHex()
	if len(hexStr) != 64 {
		t.Errorf("hex length = %d, want 64", len(hexStr))
	}
	_, err = hex.DecodeString(hexStr)
	if err != nil {
		t.Errorf("invalid hex string: %v", err)
	}
}

func TestSign(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	data := []byte("test message")
	sig := identity.Sign(data)
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
}

func TestSignHex(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	data := []byte("test message")
	sigHex := identity.SignHex(data)
	if len(sigHex) != 128 {
		t.Errorf("hex signature length = %d, want 128", len(sigHex))
	}
}

func TestPadUnpadRoundtrip(t *testing.T) {
	data := []byte("Hello, World!")
	padded, err := PadPayload(data)
	if err != nil {
		t.Fatalf("PadPayload failed: %v", err)
	}
	if len(padded)%PaddingBlock != 0 {
		t.Errorf("padded length %d is not a multiple of %d", len(padded), PaddingBlock)
	}
	unpadded, err := UnpadPayload(padded)
	if err != nil {
		t.Fatalf("UnpadPayload failed: %v", err)
	}
	if !bytes.Equal(unpadded, data) {
		t.Errorf("unpadded = %v, want %v", unpadded, data)
	}
}

func TestPadEmpty(t *testing.T) {
	padded, err := PadPayload([]byte{})
	if err != nil {
		t.Fatalf("PadPayload failed: %v", err)
	}
	if len(padded)%PaddingBlock != 0 {
		t.Errorf("padded length %d is not a multiple of %d", len(padded), PaddingBlock)
	}
	unpadded, err := UnpadPayload(padded)
	if err != nil {
		t.Fatalf("UnpadPayload failed: %v", err)
	}
	if len(unpadded) != 0 {
		t.Errorf("unpadded length = %d, want 0", len(unpadded))
	}
}

func TestUnpadEmpty(t *testing.T) {
	_, err := UnpadPayload([]byte{})
	if err == nil {
		t.Error("expected error for empty payload")
	}
}

func TestMakeSignedEnvelope(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	envelope, err := MakeSignedEnvelope(identity, "aabbccdd", "deadbeef", false)
	if err != nil {
		t.Fatalf("MakeSignedEnvelope failed: %v", err)
	}
	if envelope.RecipientID != "aabbccdd" {
		t.Errorf("recipient_id = %s, want aabbccdd", envelope.RecipientID)
	}
	if envelope.PayloadHex != "deadbeef" {
		t.Errorf("payload_hex = %s, want deadbeef", envelope.PayloadHex)
	}
	if envelope.SenderID != identity.PublicKeyHex() {
		t.Errorf("sender_id mismatch")
	}
}

func TestVersion(t *testing.T) {
	if Version != "3.0.0" {
		t.Errorf("Version = %s, want 3.0.0", Version)
	}
}
