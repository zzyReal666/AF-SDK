package com.szaf.exception;

public class AFSocketException extends Exception {
    public AFSocketException() {
    }

    public AFSocketException(String msg) {
        super(msg);
    }

    public AFSocketException(String message, Throwable cause) {
        super(message, cause);
    }

    public AFSocketException(Throwable cause) {
        super(cause);
    }
}
