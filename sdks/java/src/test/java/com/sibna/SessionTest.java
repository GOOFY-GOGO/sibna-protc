package com.sibna;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;
import com.sibna.protocol.DoubleRatchet;
import com.sibna.protocol.DoubleRatchet.Stats;
import com.sibna.crypto.CryptoProvider;
import com.sibna.exceptions.CryptoException;
import com.sibna.exceptions.SibnaException;

public class SessionTest {
    private CryptoProvider crypto;
    private byte[] sharedSecret;

    @BeforeEach
    public void setUp() {
        crypto = new CryptoProvider();
        sharedSecret = crypto.generateKey();
    }

    @Test
    public void testSessionEncryptDecryptRoundtrip() throws CryptoException {
        // Setup two parties with the same shared secret
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        DoubleRatchet bob = new DoubleRatchet(crypto, sharedSecret, false);

        byte[] plaintext = "Hello Sibna Production!".getBytes();
        byte[] ad = "associated data".getBytes();

        // Alice encrypts
        byte[] ciphertext = alice.encrypt(plaintext);
        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > plaintext.length);

        // Bob decrypts
        byte[] decrypted = bob.decrypt(ciphertext);
        assertArrayEquals(plaintext, decrypted, "Decrypted plaintext should match original");
    }

    @Test
    public void testSessionReplayProtection() throws CryptoException {
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        DoubleRatchet bob = new DoubleRatchet(crypto, sharedSecret, false);

        byte[] plaintext = "replay test".getBytes();
        byte[] ct = alice.encrypt(plaintext);

        // First decryption should work
        assertDoesNotThrow(() -> bob.decrypt(ct));

        // Second decryption of same ciphertext should fail (replay protection)
        // In DoubleRatchet.java, this happens because receivingMessageNumber increases
        // and the same message number is rejected.
        assertThrows(CryptoException.class, () -> bob.decrypt(ct));
    }

    @Test
    public void testSessionInvalidPlaintext() {
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        
        // Assuming empty plaintext should fail (C++ test does this)
        // Note: We need to implement this check in DoubleRatchet.java if not present.
        byte[] empty = new byte[0];
        assertThrows(Exception.class, () -> alice.encrypt(empty));
    }

    @Test
    public void testSessionShortCiphertext() {
        DoubleRatchet bob = new DoubleRatchet(crypto, sharedSecret, false);
        byte[] shortCt = {0x01, 0x02};
        
        assertThrows(CryptoException.class, () -> bob.decrypt(shortCt));
    }

    @Test
    public void testSessionStats() throws CryptoException {
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        
        Stats statsBefore = alice.getStats();
        assertEquals(0, statsBefore.messagesSent);
        assertEquals(0, statsBefore.messagesReceived);

        alice.encrypt("msg1".getBytes());
        alice.encrypt("msg2".getBytes());

        Stats statsAfter = alice.getStats();
        assertEquals(2, statsAfter.messagesSent);
    }

    @Test
    public void testSessionSerializationRoundtrip() throws CryptoException {
        DoubleRatchet alice = new DoubleRatchet(crypto, sharedSecret, true);
        
        // Send a message to change state
        alice.encrypt("state change".getBytes());
        
        byte[] serialized = alice.serialize();
        assertNotNull(serialized);
        assertTrue(serialized.length >= 128);

        DoubleRatchet restored = DoubleRatchet.deserialize(crypto, serialized);
        
        // Verify restored stats
        assertEquals(alice.getStats().messagesSent, restored.getStats().messagesSent);
        
        // Verify restored session can still encrypt
        byte[] ct = restored.encrypt("after restore".getBytes());
        assertNotNull(ct);
    }
}
