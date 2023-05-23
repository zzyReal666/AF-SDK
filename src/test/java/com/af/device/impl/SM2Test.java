package com.af.device.impl;

import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.crypto.struct.impl.sm2.SM2Cipher;
import com.af.crypto.struct.impl.sm2.SM2Signature;
import com.af.exception.AFCryptoException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class SM2Test {

    static AFHsmDevice device;
    static byte[] data = "1234560abcdefgh0".getBytes();

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        device = AFHsmDevice.getInstance("192.168.1.224", 8008, "abcd1234");
    }


    /**
     * 获取密钥
     */
    @Test
    void testSM2() throws Exception {

        //SM2 签名公钥
        SM2PublicKey sm2SignPublicKey = device.getSM2SignPublicKey(4, ModulusLength.LENGTH_256);
        System.out.println(sm2SignPublicKey);
        SM2PublicKey sm2SignPublicKey2 = device.getSM2SignPublicKey(4, ModulusLength.LENGTH_512);
        System.out.println(sm2SignPublicKey2);

        //SM2 加密公钥
        SM2PublicKey sm2EncryptPublicKey = device.getSM2EncryptPublicKey(2, ModulusLength.LENGTH_256);
        System.out.println(sm2EncryptPublicKey);
        SM2PublicKey sm2EncryptPublicKey1 = device.getSM2EncryptPublicKey(2, ModulusLength.LENGTH_512);
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
    void testInside256() throws AFCryptoException {
        SM2Cipher sm2Cipher = device.SM2Encrypt(ModulusLength.LENGTH_256, 2, data);
        byte[] decrypt = device.SM2Decrypt(ModulusLength.LENGTH_256, 2, sm2Cipher);
        assert Arrays.equals(data, decrypt);
    }

    @Test
    void testInside512() throws AFCryptoException {
        SM2Cipher sm2Cipher = device.SM2Encrypt(ModulusLength.LENGTH_512, 2, data);
        System.out.println("sm2Cipher:" + sm2Cipher);
        byte[] decrypt = device.SM2Decrypt(ModulusLength.LENGTH_512, 2, sm2Cipher);
        assert Arrays.equals(data, decrypt);
    }

    /**
     * 外部加解密
     * 256可以加密,解密失败  报错:SM2解密错误,错误信息:未知错误[0x01000023]
     * 512加密就失败        报错:SM2加密错误,错误信息:未知错误[0x01000023]
     */
    @Test
    void testExternal256() throws AFCryptoException {
        //256
        SM2KeyPair sm2KeyPair1 = device.generateSM2KeyPair(ModulusLength.LENGTH_256);
        SM2Cipher sm2Cipher = device.SM2Encrypt(ModulusLength.LENGTH_256, sm2KeyPair1.getPubKey(), data);
        byte[] decrypt = device.SM2Decrypt(ModulusLength.LENGTH_256, sm2KeyPair1.getPriKey(), sm2Cipher);
        assert Arrays.equals(data, decrypt);
    }


    @Test
    void testExternal512() throws AFCryptoException {
        //512
        SM2KeyPair sm2KeyPair2 = device.generateSM2KeyPair(ModulusLength.LENGTH_512);
//        SM2Cipher sm2Cipher2 = device.SM2Encrypt(ModulusLength.LENGTH_512, sm2KeyPair2.getPubKey(), data);
        //下面这句降外部key由512改为256 就可以加密
        SM2Cipher sm2Cipher2 = device.SM2Encrypt(ModulusLength.LENGTH_512, sm2KeyPair2.getPubKey(), data);
        byte[] decrypt2 = device.SM2Decrypt(ModulusLength.LENGTH_512, sm2KeyPair2.getPriKey().to256(), sm2Cipher2);
        assert Arrays.equals(data, decrypt2);
    }


    /**
     * 内部签名验签256
     */
    @Test
    void testInSign256() throws AFCryptoException {
        SM2Signature sm2Signature = device.SM2Signature(ModulusLength.LENGTH_256, 1, data);
        boolean verify = device.SM2Verify(ModulusLength.LENGTH_256, 1, data, sm2Signature);
        assert verify;
    }


    /**
     * 内部签名验签512
     */
    @Test
    void testInSign512() throws AFCryptoException {
        SM2Signature sm2Signature = device.SM2Signature(ModulusLength.LENGTH_512, 1, data);
        boolean verify = device.SM2Verify(ModulusLength.LENGTH_512, 1, data, sm2Signature);
        System.out.println(verify);
        assert verify;
    }

    /**
     * 外部签名验签256
     */
    @Test
    void testExSign256() throws AFCryptoException {
        SM2KeyPair sm2KeyPair1 = device.generateSM2KeyPair(ModulusLength.LENGTH_256);
        SM2PrivateKey priKey = sm2KeyPair1.getPriKey();
        SM2PublicKey pubKey = sm2KeyPair1.getPubKey();
        SM2Signature sm2Signature = device.SM2Signature(ModulusLength.LENGTH_256, data, priKey);
        boolean verify = device.SM2Verify(ModulusLength.LENGTH_256, data,sm2Signature,pubKey);
        assert verify;
    }
    /**
     * 外部签名验签512
     */
    @Test
    void testExSign512() throws AFCryptoException {
        SM2KeyPair sm2KeyPair2 = device.generateSM2KeyPair(ModulusLength.LENGTH_512);
        SM2Signature sm2Signature2 = device.SM2Signature(ModulusLength.LENGTH_512, data, sm2KeyPair2.getPriKey());
        boolean verify2 = device.SM2Verify(ModulusLength.LENGTH_512, data,sm2Signature2, sm2KeyPair2.getPubKey());
        assert verify2;
    }
}