package com.sibna.exceptions;

/**
 * Authentication failed.
 */
public class AuthException extends SibnaException {
    public AuthException(String message) {
        super(message, 13);
    }
}
