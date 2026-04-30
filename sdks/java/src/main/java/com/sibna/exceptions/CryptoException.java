package com.sibna.exceptions;

/**
 * Cryptographic operation failed.
 */
public class CryptoException extends SibnaException {
    public CryptoException(String message) {
        super(message, 3);
    }
    public CryptoException(String message, Throwable cause) {
        super(message + ": " + cause.getMessage(), 3);
    }
}
