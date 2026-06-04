"""
Sibna Protocol Python SDK — Unit Tests
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sibna.client import (
    Identity, SibnaClient, AsyncSibnaClient,
    pad_payload, unpad_payload,
    make_signed_envelope, verify_signed_envelope,
    SibnaError, AuthError, NetworkError, CryptoError,
)


class TestIdentity:
    def test_generate_identity(self):
        identity = Identity()
        assert len(identity.public_key_bytes) == 32
        assert len(identity.private_key_bytes) == 32
        assert len(identity.public_key_hex) == 64

    def test_sign_verify(self):
        identity = Identity()
        data = b"test message"
        sig = identity.sign(data)
        assert len(sig) == 64

        # Verify with public key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        vk = Ed25519PublicKey.from_public_bytes(identity.public_key_bytes)
        vk.verify(sig, data)  # Should not raise

    def test_sign_hex(self):
        identity = Identity()
        sig_hex = identity.sign_hex(b"test")
        assert len(sig_hex) == 128  # 64 bytes * 2 hex chars

    def test_save_load(self, tmp_path):
        identity = Identity()
        path = tmp_path / "identity.bin"
        identity.save(str(path))

        loaded = Identity.load(str(path))
        assert loaded.public_key_bytes == identity.public_key_bytes

    def test_repr(self):
        identity = Identity()
        r = repr(identity)
        assert "Identity" in r
        assert "..." in r


class TestPadding:
    def test_pad_unpad_roundtrip(self):
        data = b"Hello, World!"
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        unpadded = unpad_payload(padded)
        assert unpadded == data

    def test_pad_empty(self):
        padded = pad_payload(b"")
        unpadded = unpad_payload(padded)
        assert unpadded == b""

    def test_pad_large(self):
        data = b"x" * 5000
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        unpadded = unpad_payload(padded)
        assert unpadded == data

    def test_unpad_empty_raises(self):
        with pytest.raises(CryptoError):
            unpad_payload(b"")


class TestSignedEnvelope:
    def test_make_verify(self):
        identity = Identity()
        envelope = make_signed_envelope(
            identity,
            recipient_id="aabbccdd",
            payload_hex="deadbeef",
        )
        assert verify_signed_envelope(envelope)

    def test_verify_tampered(self):
        identity = Identity()
        envelope = make_signed_envelope(
            identity,
            recipient_id="aabbccdd",
            payload_hex="deadbeef",
        )
        # Tamper with payload
        envelope["payload_hex"] = "deadbeef01"
        assert not verify_signed_envelope(envelope)

    def test_verify_wrong_sender(self):
        identity1 = Identity()
        identity2 = Identity()
        envelope = make_signed_envelope(
            identity1,
            recipient_id="aabbccdd",
            payload_hex="deadbeef",
        )
        # Change sender to identity2
        envelope["sender_id"] = identity2.public_key_hex
        assert not verify_signed_envelope(envelope)

    def test_envelope_fields(self):
        identity = Identity()
        envelope = make_signed_envelope(
            identity,
            recipient_id="aabbccdd",
            payload_hex="deadbeef",
            compress=True,
        )
        assert envelope["recipient_id"] == "aabbccdd"
        assert envelope["payload_hex"] == "deadbeef"
        assert envelope["sender_id"] == identity.public_key_hex
        assert envelope["compressed"] is True
        assert "timestamp" in envelope
        assert "message_id" in envelope
        assert "signature_hex" in envelope


class TestClient:
    def test_generate_identity(self):
        client = SibnaClient(server="http://localhost:8080")
        identity = client.generate_identity()
        assert client.identity is not None
        assert len(identity.public_key_bytes) == 32

    def test_auth_without_identity_raises(self):
        client = SibnaClient(server="http://localhost:8080")
        with pytest.raises(AuthError):
            client.authenticate()

    def test_repr(self):
        client = SibnaClient(server="http://localhost:8080")
        client.generate_identity()
        r = repr(client)
        assert "SibnaClient" in r
        assert "localhost" in r


class TestErrors:
    def test_sibna_error(self):
        err = SibnaError("test error", 400)
        assert str(err) == "test error"
        assert err.status_code == 400

    def test_auth_error(self):
        err = AuthError("auth failed", 401)
        assert err.status_code == 401

    def test_network_error(self):
        err = NetworkError("network failed", 503)
        assert err.status_code == 503

    def test_crypto_error(self):
        err = CryptoError("crypto failed")
        assert str(err) == "crypto failed"
