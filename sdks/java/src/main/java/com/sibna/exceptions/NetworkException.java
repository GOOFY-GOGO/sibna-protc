package com.sibna.exceptions;

/**
 * Network or server error.
 */
public class NetworkException extends SibnaException {
    public NetworkException(String message) {
        super(message, 2);
    }
    public NetworkException(String message, Throwable cause) {
        super(message + ": " + cause.getMessage(), 2);
    }
}
