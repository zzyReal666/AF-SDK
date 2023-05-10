package com.af.device.impl;

import com.af.exception.AFCryptoException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SM3Test {

    static AFHsmDevice device;
    static byte[] data = "1234567812345678".getBytes();

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        device = AFHsmDevice.getInstance("192.168.1.224", 8008, "abcd1234");
    }
    @Test
    void SM3Hash() throws AFCryptoException {
        byte[] bytes = device.SM3Hash(data);
    }

    @Test
    void SM3HashWithPubKey() {

    }

    @Test
    void SM3HMac() {
    }

}