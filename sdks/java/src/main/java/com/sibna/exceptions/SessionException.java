package com.sibna.exceptions;

/**
 * Session error.
 */
public class SessionException extends SibnaException {
    public SessionException(String message) {
        super(message, 6);
    }
}
