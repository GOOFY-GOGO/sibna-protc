package com.sibna.exceptions;

/**
 * Base exception for all Sibna SDK errors.
 */
public class SibnaException extends Exception {
    private final int code;

    public SibnaException(String message) {
        super(message);
        this.code = -1;
    }

    public SibnaException(String message, Throwable cause) {
        super(message, cause);
        this.code = -1;
    }

    public SibnaException(String message, int code) {
        super(message);
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
