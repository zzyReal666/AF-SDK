package com.af.exception;

public class AFParseConfigException extends Exception {
    public AFParseConfigException() {
    }

    public AFParseConfigException(String message) {
        super(message);
    }

    public AFParseConfigException(Throwable cause) {
        super(cause);
    }

    public AFParseConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
