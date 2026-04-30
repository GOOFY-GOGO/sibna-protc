package com.sibna.exceptions;

/**
 * Rate limit exceeded.
 */
public class RateLimitException extends SibnaException {
    public RateLimitException(String message) {
        super(message, 9);
    }
}
