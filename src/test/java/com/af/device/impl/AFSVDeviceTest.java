package com.af.device.impl;

import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.device.AFDeviceFactory;
import com.af.device.DeviceInfo;
import com.af.struct.impl.RSA.RSAKeyPair;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.logging.Logger;


class
AFSVDeviceTest {

    //日志
    static Logger logger = Logger.getLogger("AFSVDeviceTest");

    //        static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.1.232", 6001, "abcd1234");
    static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.10.40", 8013, "abcd1234");
    static byte[] data = "1234567890abcdef".getBytes();

    //证书文件路径
    static String userCertFileSM2 = "src\\test\\resources\\user.crt";
    static String userCertFileRSA = "src\\test\\resources\\user.crt";

    //签名文件路径
    static byte[] fileName = "src\\test\\resources\\singFile.txt".getBytes(StandardCharsets.UTF_8);


    //SM2公钥  base64
    static String sm2PubKeyDataBase64 = "AAEAAIHQcN4xEd3myIvZRFdf+M2jtBbh3Ik8aON7J55A91AAApm2+TtovD7Pl5dSQ/5RFbQcZQk9pm3orfKkgRYp/kY=";
    //SM2私钥 base64
    static String sm2PrvKeyDataBase64 = "AAEAAEnKCb0n669m/apkWqAOfz6MsQZD68yIShAbmdQ5MMDK";


    @AfterAll
    static void tearDown() throws Exception {
        logger.info("发送关闭连接请求");
        device.close(AFSVDevice.client);
        logger.info("已经关闭连接");
    }


    /**
     * 关闭连接 success
     */
    @Test
    void testClose() throws Exception {
        device.close(AFSVDevice.client);
    }

    /**
     * 获取私钥访问权限
     */
    @Test
    void testGetPrivateKeyAccessRight() throws Exception {
        device.getPrivateAccess(1, 4);
    }

    /**
     * 密钥协商  success
     */
    @Test
    void testAgreeKey() throws Exception {
        AFSVDevice afsvDevice = device.setAgKey();
        System.out.println(afsvDevice);
    }


    //todo  ==================================以下和协议一一对应===============================================================

    /**
     * 获取设备信息
     */
    @Test
    void testGetDeviceInfo() throws Exception {
        DeviceInfo deviceInfo = device.getDeviceInfo();
        System.out.println(deviceInfo);
    }

    /**
     * 随机数
     */
    @Test
    void testGetRandom2() throws Exception {
        //开始时间
        long start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            byte[] random = device.getRandom(5);
            System.out.println(Arrays.toString(random));
        }
        //结束时间
        long end = System.currentTimeMillis();
        System.out.println("耗时：" + (end - start) + "ms");

    }

    //导出公钥信息
    @Test
    void testGetPublicKey() throws Exception {
        //RSA签名
        byte[] rsaPublicKey = device.getRSAPublicKey(1, 0);
        System.out.println("RSA签名公钥:" + new String(rsaPublicKey));
        //RSA加密
        byte[] rsaPublicKey2 = device.getRSAPublicKey(1, 1);
        System.out.println("RSA加密公钥:" + new String(rsaPublicKey2));
        //SM2 签名
        byte[] sm2PublicKey = device.getSm2PublicKey(1, 0);
        System.out.println("SM2签名公钥:" + new String(sm2PublicKey));
        //SM2加密
        byte[] sm2PublicKey2 = device.getSm2PublicKey(1, 1);
        System.out.println("SM2加密公钥:" + new String(sm2PublicKey2));
    }

    //生成密钥对
    @Test
    void testGenerateKeyPair() throws Exception {
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(0, ModulusLength.LENGTH_256);
        System.out.println("Sm2签名密钥对:" + sm2KeyPair);
        SM2KeyPair sm2KeyPair1 = device.generateSM2KeyPair(1, ModulusLength.LENGTH_256);
        System.out.println("Sm2加密密钥对:" + sm2KeyPair1);
        SM2KeyPair sm2KeyPair2 = device.generateSM2KeyPair(2, ModulusLength.LENGTH_256);
        System.out.println("Sm2密钥交换密钥对:" + sm2KeyPair2);
        SM2KeyPair sm2KeyPair3 = device.generateSM2KeyPair(3, ModulusLength.LENGTH_256);
        System.out.println("Sm2密钥对:" + sm2KeyPair3);

        RSAKeyPair rsaKeyPair = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        System.out.println("RSA密钥对:" + rsaKeyPair);
    }



    //RSA 操作
    @Test
    void testRSA() throws Exception {

        //RSA 内部签名验签
        byte[] bytes = device.rsaSignature(1, data);
        boolean b = device.rsaVerify(1, data, bytes);

        //RSA 外部签名验签
        RSAKeyPair rsaKeyPair = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        byte[] bytes1 = device.rsaSignature(rsaKeyPair.getPriKey().encode(), data);
        boolean b1 = device.rsaVerify(rsaKeyPair.getPubKey().encode(), data, bytes1);

        //RSA内部密钥加解密
        byte[] bytes2 = device.rsaEncrypt(1, data);
        byte[] bytes3 = device.rsaDecrypt(1, bytes2);
        assert Arrays.equals(data, bytes3);

        //RSA 外部密钥加解密
        byte[] bytes4 = device.rsaEncrypt(rsaKeyPair.getPubKey().encode(), data);
        byte[] bytes5 = device.rsaDecrypt(rsaKeyPair.getPriKey().encode(), bytes4);
        assert Arrays.equals(data, bytes5);

    }

    //SM2 操作
    @Test
    void testSM2() throws Exception {
        //SM2 内部签名验签
        byte[] bytes = device.sm2Signature(1, data);
        boolean b = device.sm2Verify(1, data, bytes);
        assert b;

        //SM2 外部签名验签
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(0, ModulusLength.LENGTH_256);
        byte[] bytes1 = device.sm2Signature(sm2KeyPair.getPriKey().encode(), data);
        boolean b1 = device.sm2VerifyByPublicKey(sm2KeyPair.getPubKey().encode(), data, bytes1);
        assert b1;

        //SM2内部密钥加解密
        byte[] bytes2 = device.sm2Encrypt(1, data);
        byte[] bytes3 = device.sm2Decrypt(1, bytes2);
        assert Arrays.equals(data, bytes3);

        //SM2 外部密钥加解密
        SM2KeyPair sm2KeyPair1 = device.generateSM2KeyPair(1, ModulusLength.LENGTH_256);
        byte[] bytes4 = device.sm2Encrypt(sm2KeyPair1.getPubKey().encode(), data);
        byte[] bytes5 = device.sm2Decrypt(sm2KeyPair1.getPriKey().encode(), bytes4);
        assert Arrays.equals(data, bytes5);


    }

    //对称操作 批量对称
    @Test
    void testSymmetric() throws Exception {
        //批量加密


        //批量解密

    }


}