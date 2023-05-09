package com.af.device.impl;

import com.af.exception.AFCryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class SM4Test {
    static AFHsmDevice device;
    static byte[] data = "1234567812345678".getBytes();

    @BeforeEach
    void setUp() {
        device = AFHsmDevice.getInstance("192.168.1.224", 8008, "abcd1234");
    }


    //Mac
    @Test
    void testMacInside() throws AFCryptoException {
        byte[] IV = device.getRandom(16);
        byte[] bytes = device.SM4Mac(2, data, IV);
        System.out.println(Arrays.toString(bytes));
    }

    @Test
    void testMacExternal() throws AFCryptoException {
        byte[] IV = device.getRandom(16);
        byte[] key = device.getRandom(16);
        byte[] bytes = device.SM4Mac(key, data, IV);
        System.out.println(Arrays.toString(bytes));

    }

}