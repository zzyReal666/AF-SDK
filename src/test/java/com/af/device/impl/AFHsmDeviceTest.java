package com.af.device.impl;

import cn.hutool.core.io.FileUtil;
import com.af.constant.Algorithm;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.crypto.key.symmetricKey.SessionKey;
import com.af.device.AFDeviceFactory;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPubKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class
AFHsmDeviceTest {

    static AFHsmDevice device;
//    static byte[] data = "123456788765432".getBytes(StandardCharsets.UTF_8);

    static byte[] data = FileUtil.readBytes("D:\\test.zip");

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        device = AFDeviceFactory.getAFHsmDevice("192.168.10.40", 8013, "abcd1234");
    }


    /**
     * 密钥协商  success
     */
    @Test
    void testAgreeKey() throws Exception {
        AFHsmDevice afHsmDevice = device.setAgKey();
        System.out.println(afHsmDevice);
    }

    /**
     * 获取私钥访问权限 success
     */
    @Test
    void testGetPrivateAccess() throws Exception {

    }

    /**
     * 获取设备信息 success
     */
    @Test
    void testGetDeviceInfo() throws Exception {
        System.out.println(device.getDeviceInfo());
    }

    /**
     * 获取随机数  success
     */
    @Test
    void testGetRandom() throws Exception {
        System.out.println(Arrays.toString(device.getRandom(5)));

    }

    //导出公钥 success
    @Test
    void testExportPublicKey() throws Exception {
        //SM2
        SM2PublicKey sm2EncryptPublicKey = device.getSM2EncryptPublicKey(1);
        System.out.println("SM2加密公钥:" + sm2EncryptPublicKey);
        SM2PublicKey sm2SignPublicKey = device.getSM2SignPublicKey(1);
        System.out.println("SM2签名公钥:" + sm2SignPublicKey);

        //RSA
        RSAPubKey rsaSignPublicKey = device.getRSASignPublicKey(1);
        System.out.println("RSA签名公钥:" + rsaSignPublicKey);
        RSAPubKey rsaEncryptPublicKey = device.getRSAEncPublicKey(1);
        System.out.println("RSA加密公钥:" + rsaEncryptPublicKey);

    }


    //生成密钥对 success
    @Test
    void testGenerateKeyPair() throws Exception {
        //SM2
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(0);
        System.out.println("SM2签名密钥对:" + sm2KeyPair);
        SM2KeyPair sm2KeyPair1 = device.generateSM2KeyPair(1);
        System.out.println("SM2加密密钥对:" + sm2KeyPair1);
        SM2KeyPair sm2KeyPair2 = device.generateSM2KeyPair(2);
        System.out.println("SM2密钥交换密钥对:" + sm2KeyPair2);
        SM2KeyPair sm2KeyPair3 = device.generateSM2KeyPair(3);
        System.out.println("SM2默认密钥对:" + sm2KeyPair3);

        //RSA
        RSAKeyPair rsaKeyPair = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        System.out.println("RSA1024密钥对:" + rsaKeyPair);
        RSAKeyPair rsaKeyPair1 = device.generateRSAKeyPair(ModulusLength.LENGTH_2048);
        System.out.println("RSA2048密钥对:" + rsaKeyPair1);

    }

    //生成会话密钥 导入会话密钥密文 释放密钥信息 success
    @Test
    void testReleaseKeyPair() throws Exception {

        //生成 SM2加密的会话密钥
        SessionKey key = device.generateSessionKey(Algorithm.SGD_SM2_2, 1, 16);
        System.out.println("会话密钥SGD_SM2_2:" + key);
        //导入会话密钥密文
        SessionKey key1 = device.importSessionKey(Algorithm.SGD_SM2_2, 1, key.getKey());
        System.out.println("导入会话密钥SGD_SM2_2:" + key1);
        //释放密钥信息
        device.releaseSessionKey(key.getId());


        //生成 RSA加密的会话密钥
        SessionKey key2 = device.generateSessionKey(Algorithm.SGD_RSA_ENC, 1, 16);
        System.out.println("会话密钥 SGD_RSA_ENC:" + key2);
        //导入会话密钥密文
        SessionKey key3 = device.importSessionKey(Algorithm.SGD_RSA_ENC, 1, key2.getKey());
        System.out.println("导入会话密钥 SGD_RSA_ENC:" + key3);
        //释放密钥信息
        device.releaseSessionKey(key2.getId());


        //生成 SM4加密的会话密钥
        SessionKey key4 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
        System.out.println("会话密钥SGD_SMS4_ECB:" + key4);
        //导入会话密钥密文
        SessionKey key5 = device.importSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, key4.getKey());
        System.out.println("导入会话密钥SGD_SMS4_ECB:" + key5);
        //释放密钥信息
        device.releaseSessionKey(key4.getId());

        //生成 SM1加密的会话密钥
        SessionKey key6 = device.generateSessionKeyBySym(Algorithm.SGD_SM1_ECB, 1, 16);
        System.out.println("会话密钥SGD_SM1_ECB:" + key6);
        //导入会话密钥密文
        SessionKey key7 = device.importSessionKeyBySym(Algorithm.SGD_SM1_ECB, 1, key6.getKey());
        System.out.println("导入会话密钥SGD_SM1_ECB:" + key7);
        //释放密钥信息
        device.releaseSessionKey(key6.getId());

    }


    //数字信封转换
    @Test
    void testEnvelope() throws Exception {
        //SM2
        //生成SM2密钥对
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(1);
        System.out.println("SM2密钥对:" + sm2KeyPair);
        //使用内部密钥加密data
    }

    //RSA操作 success
    @Test
    void testRSA() throws Exception {
        //生成RSA密钥对
        RSAKeyPair rsaKeyPair = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        System.out.println("RSA1024密钥对:" + rsaKeyPair);
        //使用内部密钥加解密
        byte[] encodeData = device.rsaInternalEncrypt(1, data);
        byte[] decodeData = device.rsaInternalDecrypt(1, encodeData);
        assert Arrays.equals(data, decodeData);

        //使用外部密钥加解密
        byte[] encodeData1 = device.rsaExternalEncrypt(rsaKeyPair.getPubKey(), data);
        byte[] decodeData1 = device.rsaExternalDecrypt(rsaKeyPair.getPriKey(), encodeData1);
        assert Arrays.equals(data, decodeData1);

        //使用内部密钥签名验签
        byte[] sign = device.rsaInternalSign(1, data);
        boolean verify = device.rsaInternalVerify(1, sign, data);
        assert verify;

        //使用外部密钥签名验签
        byte[] sign1 = device.rsaExternalSign(rsaKeyPair.getPriKey(), data);
        boolean verify1 = device.rsaExternalVerify(rsaKeyPair.getPubKey(), sign1, data);
        assert verify1;


    }


    //SM2操作 success
    @Test
    void testSM2() throws Exception {
        //生成SM2密钥对
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(1);
        System.out.println("SM2密钥对:" + sm2KeyPair);
        //使用内部密钥加解密
        byte[] encodeData = device.sm2InternalEncrypt(1, data);
        byte[] decodeData = device.sm2InternalDecrypt(1, encodeData);
        assert Arrays.equals(data, decodeData);

        //使用外部密钥加解密
        byte[] encodeData1 = device.sm2ExternalEncrypt(sm2KeyPair.getPubKey(), data);
        byte[] decodeData1 = device.sm2ExternalDecrypt(sm2KeyPair.getPriKey(), encodeData1);
        assert Arrays.equals(data, decodeData1);

        //使用内部密钥签名验签
        byte[] sign = device.sm2InternalSign(1, data);
        boolean verify = device.sm2InternalVerify(1, data, sign);
        assert verify;

        //使用外部密钥签名验签
        byte[] sign1 = device.sm2ExternalSign(sm2KeyPair.getPriKey(), data);
        boolean verify1 = device.sm2ExternalVerify(sm2KeyPair.getPubKey(), data, sign1);
        assert verify1;
    }

    //对称加解密
    @Test
    void testSym() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        //iv
        byte[] iv = device.getRandom(16);

        //SM4 ECB 内部
        byte[] encodeData = device.sm4InternalEncryptECB(1,data);
        byte[] decodeData = device.sm4InternalDecryptECB(1,encodeData);
        assert Arrays.equals(data,decodeData);

        //SM4 ECB 外部
        byte[] encodeData1 = device.sm4ExternalEncryptECB(key,data);
        byte[] decodeData1 = device.sm4ExternalDecryptECB(key,encodeData1);
        assert Arrays.equals(data,decodeData1);

        //SM4 ECB 密钥句柄
        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
        byte[] bytes = device.sm4HandleEncryptECB(key1.getId(), data);
        byte[] bytes1 = device.sm4HandleDecryptECB(key1.getId(), bytes);
        //释放
        device.releaseSessionKey(key1.getId());
        assert Arrays.equals(data,bytes1);

        //SM4 CBC 内部
        byte[] encodeData2 = device.sm4InternalEncryptCBC(1,iv,data);
        byte[] decodeData2 = device.sm4InternalDecryptCBC(1,iv,encodeData2);
        assert Arrays.equals(data,decodeData2);

        //SM4 CBC 外部
        byte[] encodeData3 = device.sm4ExternalEncryptCBC(key,iv,data);
        byte[] decodeData3 = device.sm4ExternalDecryptCBC(key,iv,encodeData3);
        assert Arrays.equals(data,decodeData3);

        //SM4 CBC 密钥句柄
        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
        byte[] bytes2 = device.sm4HandleEncryptCBC(key2.getId(), iv, data);
        byte[] bytes3 = device.sm4HandleDecryptCBC(key2.getId(), iv, bytes2);
        //释放密钥句柄
        device.releaseSessionKey(key2.getId());
        assert Arrays.equals(data,bytes3);


        //SM1 ECB 内部
        byte[] encodeData4 = device.sm1InternalEncryptECB(1,data);
        byte[] decodeData4 = device.sm1InternalDecryptECB(1,encodeData4);
        assert Arrays.equals(data,decodeData4);

        //SM1 ECB 外部
        byte[] encodeData5 = device.sm1ExternalEncryptECB(key,data);
        byte[] decodeData5 = device.sm1ExternalDecryptECB(key,encodeData5);
        assert Arrays.equals(data,decodeData5);

        //SM1 ECB 密钥句柄
        SessionKey key3 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
        byte[] bytes4 = device.sm1HandleEncryptECB(key3.getId(), data);
        byte[] bytes5 = device.sm1HandleDecryptECB(key3.getId(), bytes4);
        //释放密钥句柄
        device.releaseSessionKey(key3.getId());
        assert Arrays.equals(data,bytes5);


        //SM1 CBC 内部
        byte[] encodeData6 = device.sm1InternalEncryptCBC(1,iv,data);
        byte[] decodeData6 = device.sm1InternalDecryptCBC(1,iv,encodeData6);
        assert Arrays.equals(data,decodeData6);

        //SM1 CBC 外部
        byte[] encodeData7 = device.sm1ExternalEncryptCBC(key,iv,data);
        byte[] decodeData7 = device.sm1ExternalDecryptCBC(key,iv,encodeData7);
        assert Arrays.equals(data,decodeData7);

        //SM1 CBC 密钥句柄
        SessionKey key4 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
        byte[] bytes6 = device.sm1HandleEncryptCBC(key4.getId(), iv, data);
        byte[] bytes7 = device.sm1HandleDecryptCBC(key4.getId(), iv, bytes6);
        //释放密钥句柄
        device.releaseSessionKey(key4.getId());
        assert Arrays.equals(data,bytes7);


    }


    //批量对称加解密
//    @Test

}