package com.szaf.exception;

public class AFCryptoException extends Exception {
    public AFCryptoException() {
    }

    public AFCryptoException(String msg) {
        super(msg);
    }

    public AFCryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public AFCryptoException(Throwable cause) {
        super(cause);
    }
}
