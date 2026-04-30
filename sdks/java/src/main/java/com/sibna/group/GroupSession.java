package com.sibna.group;

import com.sibna.crypto.CryptoProvider;
import com.sibna.identity.IdentityKeyPair;
import com.sibna.exceptions.CryptoException;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Group messaging session using Sender Keys.
 *
 * Each member generates a sender key chain. Messages are encrypted with
 * the current sender key, and keys are ratcheted forward after each message.
 */
public class GroupSession {
    private final CryptoProvider crypto;
    private final byte[] groupId;
    private final IdentityKeyPair identity;
    private final Map<String, byte[]> memberSenderKeys;
    private final Map<String, Long> epochs;
    private byte[] mySenderKey;
    private long currentEpoch;
    private final Instant createdAt;
    private volatile boolean left = false;

    public GroupSession(CryptoProvider crypto, byte[] groupId, IdentityKeyPair identity) throws CryptoException {
        this.crypto = crypto;
        this.groupId = Arrays.copyOf(groupId, groupId.length);
        this.identity = identity;
        this.memberSenderKeys = new ConcurrentHashMap<>();
        this.epochs = new ConcurrentHashMap<>();
        this.currentEpoch = 0;
        this.createdAt = Instant.now();

        // Generate initial sender key
        this.mySenderKey = crypto.generateKey();
    }

    /**
     * Add a member to the group.
     */
    public void addMember(String publicKeyHex, byte[] senderKey) {
        memberSenderKeys.put(publicKeyHex, senderKey);
        epochs.put(publicKeyHex, currentEpoch);
    }

    /**
     * Remove a member from the group.
     */
    public void removeMember(String publicKeyHex) {
        byte[] key = memberSenderKeys.remove(publicKeyHex);
        if (key != null) {
            Arrays.fill(key, (byte) 0);
        }
        epochs.remove(publicKeyHex);
        // Increment epoch for membership change
        currentEpoch++;
    }

    /**
     * Import a sender key from a member.
     */
    public void importSenderKey(String publicKeyHex, byte[] senderKey) {
        memberSenderKeys.put(publicKeyHex, Arrays.copyOf(senderKey, senderKey.length));
        epochs.put(publicKeyHex, currentEpoch);
    }

    /**
     * Encrypt a group message.
     */
    public byte[] encrypt(byte[] plaintext) throws CryptoException {
        if (left) {
            throw new CryptoException("Already left the group");
        }

        // Ratchet sender key
        mySenderKey = crypto.hkdf(null, mySenderKey, "SibnaGroup_Ratchet".getBytes(), 32);

        // Encrypt with current sender key
        byte[] ciphertext = crypto.encrypt(mySenderKey, plaintext, groupId);

        return ciphertext;
    }

    /**
     * Decrypt a group message from a specific sender.
     */
    public byte[] decrypt(String senderPublicKeyHex, byte[] ciphertext) throws CryptoException {
        if (left) {
            throw new CryptoException("Already left the group");
        }

        byte[] senderKey = memberSenderKeys.get(senderPublicKeyHex);
        if (senderKey == null) {
            throw new CryptoException("No sender key for member: " + senderPublicKeyHex);
        }

        return crypto.decrypt(senderKey, ciphertext, groupId);
    }

    /**
     * Get the current sender key for distribution.
     */
    public byte[] getSenderKey() {
        return Arrays.copyOf(mySenderKey, mySenderKey.length);
    }

    /**
     * Get the group ID.
     */
    public byte[] getGroupId() {
        return Arrays.copyOf(groupId, groupId.length);
    }

    /**
     * Get current epoch.
     */
    public long getEpoch() {
        return currentEpoch;
    }

    /**
     * Get member count.
     */
    public int getMemberCount() {
        return memberSenderKeys.size();
    }

    /**
     * Leave the group and clear all keys.
     */
    public void leave() {
        left = true;
        Arrays.fill(mySenderKey, (byte) 0);
        mySenderKey = null;
        for (byte[] key : memberSenderKeys.values()) {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
        memberSenderKeys.clear();
        epochs.clear();
    }
}
