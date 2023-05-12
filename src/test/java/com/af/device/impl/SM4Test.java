package com.af.device.impl;

import com.af.constant.GroupMode;
import com.af.exception.AFCryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class SM4Test {
    static AFHsmDevice device;
    static byte[] data = "12345678123456".getBytes();
    byte[] key = "1234567812345678".getBytes();
    byte[] IV = "1234567812345678".getBytes();

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


    @Test
    void testECB() throws AFCryptoException {
        //ECB内部
        byte[] cipher = device.SM4Encrypt(GroupMode.ECB, 2, data, null);
        byte[] plain = device.SM4Decrypt(GroupMode.ECB, 2, cipher, null);
        assert Arrays.equals(data, plain);

        //ECB外部
        byte[] cipher2 = device.SM4Encrypt(GroupMode.ECB, key, data, null);
        byte[] plain2 = device.SM4Decrypt(GroupMode.ECB, key, cipher2, null);
        assert Arrays.equals(data, plain2);

    }
    @Test
    void  testCBC() throws AFCryptoException {
        //CBC内部
        byte[] cipher3 = device.SM4Encrypt(GroupMode.CBC, 2, data, IV);
        System.out.println("cipher3:" + Arrays.toString(cipher3));
        byte[] plain3 = device.SM4Decrypt(GroupMode.CBC, 2, cipher3, IV);
        System.out.println("plain3:" + Arrays.toString(plain3));
        assert Arrays.equals(data, plain3);

        //CBC外部
        byte[] cipher4 = device.SM4Encrypt(GroupMode.CBC, key, data, IV);
        byte[] plain4 = device.SM4Decrypt(GroupMode.CBC, key, cipher4, IV);
        assert Arrays.equals(data, plain4);
    }


}