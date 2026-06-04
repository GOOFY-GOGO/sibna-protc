package com.sibna;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import com.sibna.identity.IdentityKeyPair;

public class IdentityTest {

    @Test
    public void testGenerateIdentity() {
        IdentityKeyPair identity = IdentityKeyPair.generate();
        assertNotNull(identity);
        assertNotNull(identity.getPublicKey());
        assertEquals(32, identity.getPublicKey().length);
    }

    @Test
    public void testSignAndVerify() {
        IdentityKeyPair identity = IdentityKeyPair.generate();
        byte[] data = "test data".getBytes();
        
        byte[] signature = identity.sign(data);
        assertNotNull(signature);
        assertEquals(64, signature.length);
        
        boolean isValid = identity.verify(data, signature);
        assertTrue(isValid, "Signature should be valid for original data");
        
        byte[] tamperedData = "wrong data".getBytes();
        boolean isInvalid = identity.verify(tamperedData, signature);
        assertFalse(isInvalid, "Signature should be invalid for tampered data");
    }

    @Test
    public void testIdentityFromSeed() {
        byte[] seed = new byte[32];
        for(int i=0; i<32; i++) seed[i] = (byte)i;
        
        IdentityKeyPair identity1 = IdentityKeyPair.fromSeed(seed);
        IdentityKeyPair identity2 = IdentityKeyPair.fromSeed(seed);
        
        assertArrayEquals(identity1.getPublicKey(), identity2.getPublicKey(), "Identities from same seed must match");
    }
}
