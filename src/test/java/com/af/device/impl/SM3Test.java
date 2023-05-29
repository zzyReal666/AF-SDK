package com.af.device.impl;

import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.exception.AFCryptoException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class SM3Test {

    static AFHsmDevice device;
    static byte[] data = "1234567812345678".getBytes();

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        device = AFHsmDevice.getInstance("192.168.1.224", 8008, "abcd1234");
    }
    @Test
    void SM3Hash() throws AFCryptoException {
        byte[] bytes = device.sm3Hash(data);
    }

    @Test
    void SM3HashWithPubKey() {

    }

    @Test
    void SM3HMac() {
    }


    @Test
    void testSM3HashWithPublicKey256() throws Exception{
        //获取公钥
        SM2PublicKey sm2EncryptPublicKey = device.getSM2EncryptPublicKey(2, ModulusLength.LENGTH_256);
        byte[] bytes = device.sm3HashWithPubKey(data, sm2EncryptPublicKey, "1".getBytes());
        System.out.println(Arrays.toString(bytes));
    }

}