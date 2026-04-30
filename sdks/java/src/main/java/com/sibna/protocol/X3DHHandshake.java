package com.sibna.protocol;

import com.sibna.crypto.CryptoProvider;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.identity.PreKeyBundle;
import com.sibna.exceptions.CryptoException;

/**
 * X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol.
 *
 * Performs 3-4 DH operations to establish a shared secret:
 * - Initiator: DH(IK_a, SPK_b) + DH(EK_a, IK_b) + DH(EK_a, SPK_b) + optional DH(EK_a, OPK_b)
 * - Responder: Same calculations with their respective keys
 */
public class X3DHHandshake {
    private final CryptoProvider crypto;
    private final IdentityKeyPair identity;

    public X3DHHandshake(CryptoProvider crypto, IdentityKeyPair identity) {
        this.crypto = crypto;
        this.identity = identity;
    }

    /**
     * Initiate X3DH as Alice (the initiator).
     *
     * @param peerBundle The responder's PreKey bundle
     * @return 32-byte shared secret
     */
    public byte[] initiate(PreKeyBundle peerBundle) throws CryptoException {
        // Generate ephemeral key pair
        var ephemeralKeyPair = crypto.generateX25519KeyPair();

        // DH1: our_ik * peer_spk
        byte[] dh1 = crypto.x25519Agreement(
            identity.getX25519PrivateKey(),
            bytesToPublicKey(peerBundle.getSignedPrekey())
        );

        // DH2: our_ek * peer_ik
        byte[] dh2 = crypto.x25519Agreement(
            ephemeralKeyPair.getPrivate(),
            bytesToPublicKey(peerBundle.getIdentityKey())
        );

        // DH3: our_ek * peer_spk
        byte[] dh3 = crypto.x25519Agreement(
            ephemeralKeyPair.getPrivate(),
            bytesToPublicKey(peerBundle.getSignedPrekey())
        );

        // Combine DH results
        byte[] dhResults = concat(dh1, dh2, dh3);

        // Optional DH4: our_ek * peer_opk
        if (peerBundle.hasOnetimePrekey()) {
            byte[] dh4 = crypto.x25519Agreement(
                ephemeralKeyPair.getPrivate(),
                bytesToPublicKey(peerBundle.getOnetimePrekey())
            );
            dhResults = concat(dhResults, dh4);
        }

        // Derive shared secret using HKDF
        byte[] sharedSecret = crypto.hkdf(null, dhResults, "SibnaProtocol_X3DH".getBytes(), 32);

        // Clear sensitive data
        clear(dh1, dh2, dh3);

        return sharedSecret;
    }

    /**
     * Respond to X3DH as Bob (the responder).
     */
    public byte[] respond(byte[] ephemeralPublicKey, byte[] identityPublicKey, byte[] prekey) throws CryptoException {
        // DH1: our_spk * peer_ik
        byte[] dh1 = crypto.x25519Agreement(
            identity.getX25519PrivateKey(),
            bytesToPublicKey(identityPublicKey)
        );

        // DH2: our_ik * peer_ek
        byte[] dh2 = crypto.x25519Agreement(
            identity.getX25519PrivateKey(),
            bytesToPublicKey(ephemeralPublicKey)
        );

        // DH3: our_spk * peer_ek
        byte[] dh3 = crypto.x25519Agreement(
            identity.getX25519PrivateKey(),
            bytesToPublicKey(ephemeralPublicKey)
        );

        byte[] dhResults = concat(dh1, dh2, dh3);

        byte[] sharedSecret = crypto.hkdf(null, dhResults, "SibnaProtocol_X3DH".getBytes(), 32);

        clear(dh1, dh2, dh3);

        return sharedSecret;
    }

    private java.security.PublicKey bytesToPublicKey(byte[] keyBytes) throws CryptoException {
        // Simplified - in production, use proper X509 encoding
        try {
            java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("X25519");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new CryptoException("Failed to decode public key", e);
        }
    }

    private byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] arr : arrays) {
            totalLen += arr.length;
        }
        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }

    private void clear(byte[]... arrays) {
        for (byte[] arr : arrays) {
            if (arr != null) {
                java.util.Arrays.fill(arr, (byte) 0);
            }
        }
    }
}
