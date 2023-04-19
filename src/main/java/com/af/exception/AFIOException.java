package com.af.exception;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/19 17:34
 */
public class AFIOException extends RuntimeCryptoException {
    /**
     * base constructor.
     */
    public AFIOException() {
    }

    /**
     * create a RuntimeCryptoException with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public AFIOException(String message) {
        super(message);
    }
}
