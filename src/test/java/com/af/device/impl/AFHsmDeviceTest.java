package com.af.device.impl;

import com.af.constant.GroupMode;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PubKey;
import com.af.crypto.struct.impl.sm2.SM2Cipher;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class AFHsmDeviceTest {

    static AFHsmDevice device;

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        device = AFHsmDevice.getInstance("192.168.1.224", 8008, "abcd1234");
    }

    @Test
    void testGetDeviceInfo() throws Exception {
        System.out.println(device.getDeviceInfo());
    }

    //获取随机数
    @Test
    void testGetRandom() throws Exception {
        System.out.println(Arrays.toString(device.getRandom(5)));

    }

    /**
     * SM1加解密<br>
     * Todo 1.测试16倍数/非倍数 <br>
     * Todo 2.总长度超过4096 <br>
     */
    @Test
    void testSM1() throws Exception {

        byte[] key = device.getRandom(16);
        byte[] iv = device.getRandom(16);

        //内部 ECB
        byte[] data = "12345678123456".getBytes();
        byte[] encryptECB = device.SM1Encrypt(GroupMode.ECB, 2, null, data);
        byte[] decryptECB = device.SM1Decrypt(GroupMode.ECB, 2, null, encryptECB);
        assert Arrays.equals(data, decryptECB);

        //内部 CBC
        byte[] encryptCBC = device.SM1Encrypt(GroupMode.CBC, 2, iv, data);
        byte[] decryptCBC = device.SM1Decrypt(GroupMode.CBC, 2, iv, encryptCBC);
        assert Arrays.equals(data, decryptCBC);

        //外部 ECB
        byte[] encryptECB2 = device.SM1Encrypt(GroupMode.ECB, key, null, data);
        byte[] decryptECB2 = device.SM1Decrypt(GroupMode.ECB, key, null, encryptECB2);
        assert Arrays.equals(data, decryptECB2);

        //外部 CBC
        byte[] encryptCBC2 = device.SM1Encrypt(GroupMode.CBC, key, iv, data);
        byte[] decryptCBC2 = device.SM1Decrypt(GroupMode.CBC, key, iv, encryptCBC2);
        assert Arrays.equals(data, decryptCBC2);

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


        //SM2 内部加解密
        byte[] data = "12345678123456".getBytes();
        SM2Cipher sm2Cipher = device.SM2Encrypt(ModulusLength.LENGTH_512, 2, data);
        System.out.println(sm2Cipher);
        byte[] decrypt = device.SM2Decrypt(ModulusLength.LENGTH_512, 2, sm2Cipher);
        assert Arrays.equals(data, decrypt);


        //SM2 外部加解密
        SM2Cipher sm2Cipher1 = device.SM2Encrypt(ModulusLength.LENGTH_512, sm2EncryptPublicKey1, data);
        System.out.println(sm2Cipher1);




        //


    }
}