package com.sibna.exceptions;

/**
 * Invalid argument provided.
 */
public class InvalidArgumentException extends SibnaException {
    public InvalidArgumentException(String message) {
        super(message, 1);
    }
}
