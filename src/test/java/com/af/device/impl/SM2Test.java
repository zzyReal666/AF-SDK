package com.af.device.impl;

import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PubKey;
import com.af.crypto.struct.impl.sm2.SM2Cipher;
import com.af.exception.AFCryptoException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SM2Test {

    static AFHsmDevice device;
    static byte[] data = "12345678123456".getBytes();

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        device = AFHsmDevice.getInstance("192.168.1.224", 8008, "abcd1234");
    }


    @Test
    void testSM2() throws Exception {

        //SM2 签名公钥
        SM2PubKey sm2SignPublicKey = device.getSM2SignPublicKey(4, ModulusLength.LENGTH_256);
        System.out.println(sm2SignPublicKey);
        SM2PubKey sm2SignPublicKey2 = device.getSM2SignPublicKey(4, ModulusLength.LENGTH_512);
        System.out.println(sm2SignPublicKey2);

        //SM2 加密公钥
        SM2PubKey sm2EncryptPublicKey = device.getSM2EncryptPublicKey(2, ModulusLength.LENGTH_256);
        System.out.println(sm2EncryptPublicKey);
        SM2PubKey sm2EncryptPublicKey1 = device.getSM2EncryptPublicKey(2, ModulusLength.LENGTH_512);
        System.out.println(sm2EncryptPublicKey1);

        //SM2 密钥对
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(ModulusLength.LENGTH_256);
        System.out.println(sm2KeyPair);
        SM2KeyPair sm2KeyPair1 = device.generateSM2KeyPair(ModulusLength.LENGTH_512);
        System.out.println(sm2KeyPair1);


    }

    /**
     * 内部加解密
     */
    @Test
    void testInside() throws AFCryptoException {
        SM2Cipher sm2Cipher = device.SM2Encrypt(ModulusLength.LENGTH_512, 2, data);
        System.out.println(sm2Cipher);
        byte[] decrypt = device.SM2Decrypt(ModulusLength.LENGTH_512, 2, sm2Cipher);
        assert Arrays.equals(data, decrypt);
    }


    /**
     * 外部加解密
     */
    @Test
    void testExternal() throws AFCryptoException {
        //密钥
        SM2PubKey sm2EncryptPublicKey = device.getSM2EncryptPublicKey(2, ModulusLength.LENGTH_256);
        SM2PubKey sm2EncryptPublicKey1 = device.getSM2EncryptPublicKey(2, ModulusLength.LENGTH_512);
        //加解密
        SM2Cipher sm2Cipher1 = device.SM2Encrypt(ModulusLength.LENGTH_512, sm2EncryptPublicKey1, data);


        SM2Cipher sm2Cipher = device.SM2Encrypt(ModulusLength.LENGTH_256, sm2EncryptPublicKey, data);
        assert Arrays.equals(data, decrypt);

    }

}