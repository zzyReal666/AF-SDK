package com.af.device.impl;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.HexUtil;
import com.af.constant.ConstantNumber;
import com.af.constant.ModulusLength;
import com.af.crypto.algorithm.sm3.SM3Impl;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.device.DeviceInfo;
import com.af.exception.AFCryptoException;
import com.af.struct.signAndVerify.*;
import com.af.struct.signAndVerify.RSA.RSAKeyPairStructure;
import com.af.struct.signAndVerify.sm2.SM2KeyPairStructure;
import com.af.struct.signAndVerify.sm2.SM2PrivateKeyStructure;
import com.af.utils.BytesOperate;
import com.af.utils.base64.Base64;
import org.junit.Ignore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;


class AFSVDeviceTest {
    //region //初始化数据

    //日志
    static Logger logger = Logger.getLogger("AFSVDeviceTest");
    static AFSVDevice device;


    //    static byte[] data = "1234567890abcde".getBytes();
    //大数据
//    static byte[] data = FileUtil.readBytes("D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\bigData");
    static byte[] data = "1234567890abcde".getBytes(StandardCharsets.UTF_8);

    //证书文件路径
    static String userCertFileSM2 = "user.cer";
    static String deviceCertPath = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\user.cer";
    static String rootCertPath = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\root.cer";
    //userCertPrivateKey
    static String userCertPrivateKeyPath = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\userCertPrivateKey";

    //证书文件
    static byte[] userCert = FileUtil.readBytes(userCertFileSM2);
    static byte[] deviceCert = FileUtil.readBytes(deviceCertPath);
    static byte[] rootCert = FileUtil.readBytes(rootCertPath);
    //endregion

    @BeforeAll
    static void setUp() throws Exception {
//        device = new AFSVDevice.Builder("192.168.90.40", 8008, "abcd1234").build();
//        device = new AFSVDevice.Builder("192.168.90.182", 6000, "abcd1234").build();
    }

    @AfterAll
    static void tearDown() throws Exception {
//        logger.info("发送关闭连接请求");
//        device.close(AFSVDevice.getClient());
//        logger.info("已经关闭连接");
    }

    @Test
    void test3232() {
        String base64Cert = "-----BEGIN CERTIFICATE-----\r\n MIIEMjCCA9WgAwIBAgIIaeIA0AAnL0IwDAYIKoEcz1UBg3UFADCBgjELMAkGA1UEBhMCQ04xDzANBgNVBAgMBll1bm5hbjEQMA4GA1UEBwwHS3VubWluZzENMAsGA1UECgwEeW5jYTEuMCwGA1UECwwlWXVubmFuIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IENlbnRyZTERMA8GA1UEAwwIWU5DQV9TTTIwHhcNMjIwOTI5MDY0OTAwWhcNMjMwOTI5MDY0OTAwWjBpMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5YyX5Lqs5biCMRIwEAYDVQQHDAnluILovpbljLoxDzANBgNVBAUMBjY4NDk2NjEhMB8GA1UEAwwY5rWq5r2u5oC76ZuG5rWL6K+V5p2O5biFMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEw+dcbcbwvHq6easfBiE5QR/eY/2NOUAmPYtjvab8ykAlybhrBkS7LDqAledS4ziFI+oJPwVL1BnoeW5i+88jQaOCAkkwggJFMAwGA1UdEwQFMAMBAQAwKgYDVR0lAQH/BCAwHgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBDALBgNVHQ8EBAMCAMAwGgYEKgUdAQQSOTExMTAxMDYzOTk0MTQwMVhHMB8GA1UdIwQYMBaAFDjDC6Z+GXwOzw0+ouzFH2r8ubTgMIGoBgNVHR8EgaAwgZ0wgZqggZeggZSGgZFsZGFwOi8vc2xkYXAueXVubmFuY2EubmV0L0NOPVlOQ0FfU00yLENOPVlOQ0FfU00yLCBPVT1DUkxEaXN0cmlidXRlUG9pbnRzLCBvPXluY2E/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdGNsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIGiBggrBgEFBQcBAQSBlTCBkjCBjwYIKwYBBQUHMAKGgYJsZGFwOi8vc2xkYXAueXVubmFuY2EubmV0L0NOPVlOQ0FfU00yLENOPVlOQ0FfU00yLCBTVD1jQUNlcnRpZmljYXRlcywgbz15bmNhP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MB0GA1UdDgQWBBQOMN0MNeXMW3zGH3mnPaMcdzjiaTBQBgNVHSAESTBHMEUGCCqBHM9VCAEBMDkwNwYIKwYBBQUHAgEWK2h0dHA6Ly93d3cueXVubmFuY2EubmV0Lz9waWNkb3duL2lkLzIzLmh0bWwwDAYIKoEcz1UBg3UFAANJADBGAiEAjg9DulijKASqJxQZlEl8gJhcgXBahzIsXgJHJfr4T6oCIQCzxOdUFY5Et3sF5lqM8WMhWpBJnsTIYj00+WuYroYWpg==\r\n-----END CERTIFICATE-----";

        System.out.println(base64Cert);
    }

    @Test
    void azt() throws AFCryptoException {


        //获取私钥权限
        device.getPrivateAccess(11, 3, "12345678");
        //5号密钥 签名
        byte[] bytes = device.sm2Signature(11, data);
        //5号密钥 验签
        boolean b = device.sm2Verify(11, data, bytes);

        assert b;


        //导出5号密钥公钥
        byte[] sm2SignPublicKey = device.getSM2SignPublicKey(11);
        //外部密钥验签
        boolean b1 = device.sm2Verify(sm2SignPublicKey, data, bytes);
        assert b1;

        String cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDiTCCAy+gAwIBAgIIKyg/2vMP5towCgYIKoEcz1UBg3UwXTELMAkGA1UEBhMC\n" +
                "Q04xMzAxBgNVBAoMKuWMl+S6rOS4lue6qumAn+eggeS/oeaBr+enkeaKgOaciemZ\n" +
                "kOWFrOWPuDEZMBcGA1UEAwwQQ1NDQSBUZXN0IFNNMiBDQTAeFw0yMzA4MjUwNzA1\n" +
                "MThaFw0yNDA4MjUwNzA1MThaMIHgMRMwEQYDVQQqDAplbnRlcnByaXNlMQ0wCwYD\n" +
                "VQQLDARTYWFTMTYwNAYDVQQKDC3ljJfkuqzlronor4HpgJrkv6Hmga/np5HmioDo\n" +
                "gqHku73mnInpmZDlhazlj7gxCzAJBgNVBAUMAjAxMRswGQYDVQQEDBI5MTQzMDEw\n" +
                "MDY4NzQxOTQ3MjcxWDBWBgNVBAMMT+WMl+S6rOWuieivgemAmuS/oeaBr+enkeaK\n" +
                "gOiCoeS7veaciemZkOWFrOWPuOa5luWNl+WIhuWFrOWPuEA5MTQzMDEwMDY4NzQx\n" +
                "OTQ3MjcwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASB8i+lWn+vxFWTUoWoxTQk\n" +
                "86kr25UoEu9PDl9+O/DMeEeIrkkqHT/DvZLUiwDqpq4GodRyM+oxIHmeUibs9dAU\n" +
                "o4IBUzCCAU8wHwYDVR0jBBgwFoAUWqFyjnsgBON6wBFmuDigIn3Ep70wHQYDVR0O\n" +
                "BBYEFOXgJARU5zHzVryeQx5HirCVECvIMEoGA1UdIARDMEEwPwYIKoEch4Q3AQIw\n" +
                "MzAxBggrBgEFBQcCARYlaHR0cHM6Ly93d3cuY3NtYXJ0LmNvbS5jbi9jcHMvY3Bz\n" +
                "Lmh0bTAOBgNVHQ8BAf8EBAMCBsAwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly93\n" +
                "d3cuY3NtYXJ0LmNvbS5jbi9jcmwvdGVzdHNtMmNhL2NybC5jcmwwbwYIKwYBBQUH\n" +
                "AQEEYzBhMDEGCCsGAQUFBzAChiVodHRwOi8vdGVzdC5jc21hcnQuY29tLmNuL2Nh\n" +
                "aXNzdWUuaHRtMCwGCCsGAQUFBzABhiBodHRwOi8vdGVzdC5jc21hcnQuY29tLmNu\n" +
                "OjIwNDQzLzAKBggqgRzPVQGDdQNIADBFAiEAt82YivA6ABJwLEmxqdHa4b0H/P4l\n" +
                "1IUtXtmvSRrWJE4CIFZBhYj+X4NwflSFzrHzR7rLVdcRZCtzAbjm3XH7dd0p\n" +
                "-----END CERTIFICATE-----\n";
        //证书验签
        boolean b2 = device.certVerify(cert.getBytes(), data, bytes);
        assert b2;


//
//        String key = "04 06 19 12 7a 25 05 a6  4c 46 da 38 c8 1c e5 c5\n" +
//                "8e 34 c0 8a 85 89 59 d7  35 12 e1 f9 37 fd d7 82\n" +
//                "8a 6b 9f dc 1e ba 6c ba  d0 dd 26 12 bc bf e5 ce\n" +
//                "e5 24 f8 c2 8b 4e bb 03  87 48 54 52 1d 2e 50 57\n" +
//                "bc ";
//        //去除空格
//        key = key.replaceAll(" ", "");
//        //去除换行符
//        key = key.replaceAll("\n", "");
//        //十六进制解码为ASN1 der
//        byte[] decode = HexUtil.decodeHex(key);
//        //base64编码
//        byte[] encode = BytesOperate.base64EncodeData(decode);
//        //证书中的公钥验签
//        boolean b2 = device.sm2Verify(encode, data, bytes);
//        assert b2;


    }


    //心跳
    @Test
    void testHeartBeat() throws Exception {
        device.heartBeat(device.getClient(), 1);
    }


    //region //与HSM共有

    /**
     * 关闭连接 success
     */
    @Test
    void testClose() throws Exception {
//        device.close(AFSVDevice.getClient());
    }


    private AFSVDevice getDevice() {
        AFSVDevice device = new AFSVDevice.Builder("47.103.213.215", 28015, "abcd1234")
                .responseTimeOut(10000)
                .connectTimeOut(100000)
                .managementPort(443)
                .build();
        return device;
    }

    /**
     * 密钥协商  success
     */
    @Test
    void testAgreeKey() throws Exception {
        AFSVDevice afsvDevice = device.setAgKey();
        System.out.println(afsvDevice);
    }


    /**
     * 获取设备信息 success
     */
    @Test
    void testGetDeviceInfo() throws Exception {


        AFSVDevice abcd12345 = new AFSVDevice.Builder("192.168.90.182", 6005, "abcd1234").build();
        DeviceInfo deviceInfo1 = abcd12345.getDeviceInfo();
        System.out.println(deviceInfo1);
        AFSVDevice abcd1234 = new AFSVDevice.Builder("192.168.90.182", 6000, "abcd1234").build();
        DeviceInfo deviceInfo = abcd1234.getDeviceInfo();
        System.out.println(deviceInfo);
        abcd1234.close(abcd1234.getClient());
        AFSVDevice abcd123455 = new AFSVDevice.Builder("192.168.90.182", 6000, "abcd1234").build();
        DeviceInfo deviceInfo2 = abcd123455.getDeviceInfo();
        System.out.println(deviceInfo2);
    }

    /**
     * 随机数 success    todo 为什么需要base64编码
     */
    @Test
    void testGetRandom2() throws Exception {
        byte[] random = device.getRandom(5);
        System.out.println(Arrays.toString(random));
    }

    //导出公钥 success
    @Test
    void testExportPublicKey() throws Exception {
//        //SM2
//        byte[] sm2EncryptPublicKey = device.getSM2EncryptPublicKey(1);
//        System.out.println("SM2加密公钥:" + new String(sm2EncryptPublicKey));
//        byte[] sm2SignPublicKey = device.getSM2SignPublicKey(1);
//        System.out.println("SM2签名公钥:" + new String(sm2SignPublicKey));
//
//        //RSA
//        byte[] rsaSignPublicKey = device.getRSASignPublicKey(1);
//        System.out.println("RSA签名公钥:" + new String(rsaSignPublicKey));
//        byte[] rsaEncPublicKey = device.getRSAEncPublicKey(1);
//        System.out.println("RSA加密公钥:" + new String(rsaEncPublicKey));

//        String db = "AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArn/WpknD21f5d3OiSECti33kNhvLEg3f2GPwBNAfp2oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJRJp0AAlBnLp+27syoqXW9zIWaC+DR477xIcTvnSJXYAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsvfYeaKFjZlDFd8deeHGRV6DGkKD541V7N1i1cSm4+k=";


//        String db = "AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYjqsARn/WUG/sj08xOmfXbqNk+vUA18/TDlvjbQIfcYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAInupc9rB96o290m26MemOr4Ym2/wCgCvg3sj2jY93CKAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2WJBz00sb2PYczVJPMzACppPF80m2MScJ8FDcHJjQWk=";

//        String db = "AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgfIvpVp/r8RVk1KFqMU0JPOpK9uVKBLvTw5ffjvwzHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEeIrkkqHT/DvZLUiwDqpq4GodRyM+oxIHmeUibs9dAUAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYnMBadhxPDJkP5exxyRAhsW5W4hwv4x6XufKzWaioUU=";
        String db = "AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgfIvpVp/r8RVk1KFqMU0JPOpK9uVKBLvTw5ffjvwzHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEeIrkkqHT/DvZLUiwDqpq4GodRyM+oxIHmeUibs9dAUAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYnMBadhxPDJkP5exxyRAhsW5W4hwv4x6XufKzWaioUU=";

        byte[] bytes = Base64.decode(db);

        System.out.println(HexUtil.encodeHexStr(bytes));


    }


    @Test
    void temp() {
        String key = "00 04 06 19 12 7a 25 05  a6 4c 46 da 38 c8 1c e5\n" +
                "c5 8e 34 c0 8a 85 89 59  d7 35 12 e1 f9 37 fd d7\n" +
                "82 8a 6b 9f dc 1e ba 6c  ba d0 dd 26 12 bc bf e5\n" +
                "ce e5 24 f8 c2 8b 4e bb  03 87 48 54 52 1d 2e 50\n" +
                "57 bc ";
        //去除空格
        key = key.replaceAll(" ", "");
        //去除换行符
        key = key.replaceAll("\n", "");
        System.out.println(key.length());
        System.out.println("3046022100ae7fd6a649c3db57f97773a24840ad8b7de4361bcb120ddfd863f004d01fa76a0221009449a740009419cba7edbbb32a2a5d6f73216682f83478efbc48713be74895d8".length());
    }

    //生成密钥对
    @Test
    void testGenerateKeyPair() throws Exception {
        //循环100次
        for (int i = 0; i < 100; i++) {
            //SM2
            SM2KeyPairStructure sm2KeyPairStructure = device.generateSM2KeyPair(0);
            System.out.println("Sm2签名密钥对:" + sm2KeyPairStructure);
            SM2KeyPairStructure sm2KeyPairStructure1 = device.generateSM2KeyPair(1);
            System.out.println("Sm2加密密钥对:" + sm2KeyPairStructure1);
            SM2KeyPairStructure sm2KeyPairStructure2 = device.generateSM2KeyPair(2);
            System.out.println("Sm2密钥交换密钥对:" + sm2KeyPairStructure2);
            SM2KeyPairStructure sm2KeyPairStructure3 = device.generateSM2KeyPair(3);
            System.out.println("Sm2密钥对:" + sm2KeyPairStructure3);
            RSAKeyPairStructure rsaKeyPairStructure = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
            System.out.println("RSA密钥对:" + rsaKeyPairStructure);
        }

    }

    /**
     * 根据私钥计算公钥
     */
    @Test
    void testGetPublicKeyByPrivateKey() throws Exception {
        SM2KeyPairStructure sm2KeyPairStructure = device.generateSM2KeyPair(0);
        System.out.println("Sm2签名密钥对:" + sm2KeyPairStructure);

        //私钥
        byte[] sm2SignPrivateKey = sm2KeyPairStructure.getPriKey();
        //公钥
        byte[] sm2SignPublicKey = sm2KeyPairStructure.getPubKey();
        //Base64解码
        sm2SignPublicKey = BytesOperate.base64DecodeData(sm2SignPublicKey);
        System.out.println("生成公钥:" + HexUtil.encodeHexStr(sm2SignPublicKey));


        //计算公钥
        byte[] sm2PubKeyFromPriKey = device.getSM2PubKeyFromPriKey(sm2SignPrivateKey);
        System.out.println("计算出的公钥:" + HexUtil.encodeHexStr(sm2PubKeyFromPriKey));


    }


    //RSA 操作 success
    @Test
    void testRSA() throws Exception {
        //生成密钥对
        RSAKeyPairStructure rsaKeyPairStructure = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        //私钥
        byte[] rsaSignPrivateKey = rsaKeyPairStructure.getPriKey();
        //公钥
        byte[] rsaSignPublicKey = rsaKeyPairStructure.getPubKey();

        //文件路径
        byte[] fileName = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\bigData".getBytes();

        //RSA 内部签名验签 success
        device.getPrivateAccess(1, 4, "12345678");
        byte[] bytes = device.rsaSignature(1, "1234567".getBytes());
        boolean b = device.rsaVerify(1, "1234567".getBytes(), bytes);
        assert b;

        //RSA 外部签名验签
        byte[] bytes1 = device.rsaSignature(rsaSignPrivateKey, "1234567".getBytes());
        boolean b1 = device.rsaVerify(rsaSignPublicKey, "1234567".getBytes(), bytes1);
        assert b1;


    }

    //RSA文件签名验签 success
    @Test
    void testRSAFIle() throws Exception {
        //生成密钥对
        RSAKeyPairStructure rsaKeyPairStructure = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        //私钥
        byte[] rsaSignPrivateKey = rsaKeyPairStructure.getPriKey();
        //公钥
        byte[] rsaSignPublicKey = rsaKeyPairStructure.getPubKey();
        //读取文件
        byte[] dataPath = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\bigData".getBytes();

        //RSA 内部密钥文件签名验签 success
        //获取私钥权限
        device.getPrivateAccess(1, 4, "12345678");
        byte[] bytes2 = device.rsaSignFile(1, dataPath);
        boolean b2 = device.rsaVerifyFile(1, dataPath, bytes2);
        assert b2;

        //RSA 外部密钥文件签名验签
        byte[] bytes3 = device.rsaSignFile(rsaSignPrivateKey, dataPath);
        boolean b3 = device.rsaVerifyFile(rsaSignPublicKey, dataPath, bytes3);
        assert b3;

    }

    //RSA 证书验签 success todo 从证书读取公钥,调用外部公钥验签接口
    @Test
    void testRSAWithCert() throws Exception {
        //生成密钥对
        RSAKeyPairStructure rsaKeyPairStructure = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        //私钥
        byte[] rsaSignPublicKey = rsaKeyPairStructure.getPriKey();
        //公钥
        byte[] rsaEncPublicKey = rsaKeyPairStructure.getPubKey();
        //读取文件
        byte[] dataPath = "D:\\test.zip".getBytes();

        //RSA 证书验签
        byte[] bytes3 = device.rsaSignature(rsaSignPublicKey, data);
        boolean b3 = device.rsaVerify(rsaEncPublicKey, data, bytes3);
        assert b3;

        //RSA 证书 验签 文件


    }

    //RSA 加密解密
    @Test
    void testRSAEncAndDec() throws Exception {
        //生成密钥对
        RSAKeyPairStructure rsaKeyPairStructure = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        //私钥
        byte[] rsaSignPrivateKey = rsaKeyPairStructure.getPriKey();
        //公钥
        byte[] rsaSignPublicKey = rsaKeyPairStructure.getPubKey();

        //内部密钥加密解密
        byte[] bytes = device.rsaEncrypt(1, "1234567".getBytes());
        byte[] bytes1 = device.rsaDecrypt(1, bytes);
        assert Arrays.equals(bytes1, "1234567".getBytes());

        //外部密钥加密解密
        byte[] bytes2 = device.rsaEncrypt(rsaSignPublicKey, "1234567".getBytes());
        byte[] bytes3 = device.rsaDecrypt(rsaSignPrivateKey, bytes2);
        assert Arrays.equals(bytes3, "1234567".getBytes());

    }


    //SM2 签名验签  success
    @Test
    void testSM2() throws Exception {
        //生成密钥对
        SM2KeyPairStructure sm2KeyPairStructure = device.generateSM2KeyPair(0);
        //私钥
        byte[] sm2SignPrivateKey = sm2KeyPairStructure.getPriKey();
        //公钥
        byte[] sm2SignPublicKey = sm2KeyPairStructure.getPubKey();

        //设备私钥
        byte[] priKey = getPriKey();
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(priKey);
        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2PrivateKey);
        priKey = sm2PrivateKeyStructure.toASN1Primitive().getEncoded("DER");
        priKey = BytesOperate.base64EncodeData(priKey);


        //设备证书 路径
        byte[] cert = userCertFileSM2.getBytes();


        //SM2 内部签名验签 success
        device.getPrivateAccess(1, 3, "12345678");
        byte[] bytes = device.sm2Signature(1, data);
        boolean b = device.sm2Verify(1, data, bytes);
        assert b;

        //SM2 外部签名验签 success
        byte[] bytes1 = device.sm2Signature(sm2SignPrivateKey, data);
        boolean b1 = device.sm2Verify(sm2SignPublicKey, data, bytes1);
        assert b1;

//        //SM2 私钥签名 带z值
//        byte[] bytes2 = device.sm2SignatureByPrivateKey(priKey, data);
//        boolean b2 = device.sm2VerifyByCertificate(cert, data, bytes2);
//        assert b2;
//
//        //SM2 私钥签名 带证书
//        byte[] bytes3 = device.sm2SignatureByCertificate(priKey, data, cert);
//        boolean b3 = device.sm2VerifyByCertificate(cert, cert, data, bytes3);
//        assert b3;

    }


    //SM2文件签名验签
    @Test
    void testSM2File() throws Exception {
        //生成密钥对
        SM2KeyPairStructure sm2KeyPairStructure = device.generateSM2KeyPair(0);
        //私钥
        byte[] sm2SignPrivateKey = sm2KeyPairStructure.getPriKey();
        //公钥
        byte[] sm2SignPublicKey = sm2KeyPairStructure.getPubKey();

        //设备私钥
        byte[] priKey = getPriKey();
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(priKey);
        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2PrivateKey);
        priKey = sm2PrivateKeyStructure.toASN1Primitive().getEncoded("DER");
        priKey = BytesOperate.base64EncodeData(priKey);
        //设备证书
        byte[] cert = userCert;

        //读取文件
        byte[] dataPath = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\bigData".getBytes();

        //SM2 内部签名验签 success
        //获取私钥权限
        device.getPrivateAccess(1, 3, "12345678");
        byte[] bytes = device.sm2SignFile(1, dataPath);
        boolean b = device.sm2VerifyFile(1, dataPath, bytes);
        assert b;

        //SM2 外部签名验签
        byte[] bytes1 = device.sm2SignFile(sm2SignPrivateKey, dataPath);
        boolean b1 = device.sm2VerifyFile(sm2SignPublicKey, dataPath, bytes1);
        assert b1;

        //SM2 私钥签名 带z值
        byte[] bytes2 = device.sm2SignFileByPrivateKey(priKey, dataPath);
        boolean b2 = device.sm2VerifyFileByCertificate(cert, dataPath, bytes2);
        assert b2;

        //SM2 私钥签名 带证书
        byte[] bytes3 = device.sm2SignFileByCertificate(priKey, dataPath, cert);
        boolean b3 = device.sm2VerifyFileByCertificate(cert, cert, dataPath, bytes3);
        assert b3;

    }

    //SM2 加解密 success
    @Test
    void testSM2Encrypt() throws Exception {
        //生成密钥对
        SM2KeyPairStructure sm2KeyPairStructure = device.generateSM2KeyPair(0);
        //私钥
        byte[] sm2SignPrivateKey = sm2KeyPairStructure.getPriKey();
        //公钥
        byte[] sm2SignPublicKey = sm2KeyPairStructure.getPubKey();

        //设备私钥
        byte[] priKey = getPriKey();
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(priKey);
        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2PrivateKey);
        priKey = sm2PrivateKeyStructure.toASN1Primitive().getEncoded("DER");
        priKey = BytesOperate.base64EncodeData(priKey);
        //设备证书
        byte[] cert = userCert;


        //SM2 内部加解密 success
        byte[] bytes = device.sm2Encrypt(1, data);
        byte[] bytes1 = device.sm2Decrypt(1, bytes);
        assert Arrays.equals(data, BytesOperate.base64DecodeData(bytes1));

        //SM2 外部加解密 success
        byte[] bytes2 = device.sm2Encrypt(sm2SignPublicKey, data);
        byte[] bytes3 = device.sm2Decrypt(sm2SignPrivateKey, bytes2);
        assert Arrays.equals(data, BytesOperate.base64DecodeData(bytes3));


        //SM2 证书加密 外部私钥解密
        byte[] bytes4 = device.sm2EncryptByCertificate(cert, data);
        byte[] bytes5 = device.sm2Decrypt(priKey, bytes4);
        assert Arrays.equals(data, BytesOperate.base64DecodeData(bytes5));


    }

    @Test
    void testTemp() throws Exception {
        //SM2 内部加解密 success
//        device.getPrivateAccess(1, 3, "12345678");
        byte[] bytes = device.sm2Encrypt(1, data);
        byte[] bytes1 = device.sm2Decrypt(1, bytes);
        assert Arrays.equals(data, BytesOperate.base64DecodeData(bytes1));
    }

    //SM4 ECB success
    @Test
    void testSm4ECBIn() throws Exception {


        //SM4 ECB 内部
        byte[] encodeData = device.sm4InternalEncryptECB(1, data);
        byte[] decodeData = device.sm4InternalDecryptECB(1, encodeData);
        assert Arrays.equals(data, decodeData);


    }

    //SM4 ECB
    @Test
    void testSm4ECBOut() throws Exception {
        //key
        byte[] key = BytesOperate.base64DecodeData(device.getRandom(16));
        //iv
        byte[] iv = BytesOperate.base64DecodeData(device.getRandom(16));

        //SM4 ECB 外部
        byte[] encodeData1 = device.sm4ExternalEncryptECB(key, data);
        byte[] decodeData1 = device.sm4ExternalDecryptECB(key, encodeData1);
        assert Arrays.equals(data, decodeData1);

    }

    //SM4 CBC
    @Test
    void testSm4CBC() throws Exception {
        //key
        byte[] key = BytesOperate.base64DecodeData(device.getRandom(16));
        //iv
        byte[] iv = BytesOperate.base64DecodeData(device.getRandom(16));

        //SM4 CBC 内部
        byte[] encodeData2 = device.sm4InternalEncryptCBC(1, iv, data);
        byte[] decodeData2 = device.sm4InternalDecryptCBC(1, iv, encodeData2);
        assert Arrays.equals(data, decodeData2);

        //SM4 CBC 外部
        byte[] encodeData3 = device.sm4ExternalEncryptCBC(key, iv, data);
        byte[] decodeData3 = device.sm4ExternalDecryptCBC(key, iv, encodeData3);
        assert Arrays.equals(data, decodeData3);

//        //SM4 CBC 密钥句柄
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        byte[] bytes2 = device.sm4HandleEncryptCBC(key2.getId(), iv, data);
//        byte[] bytes3 = device.sm4HandleDecryptCBC(key2.getId(), iv, bytes2);
//        //释放密钥句柄
//        device.releaseSessionKey(key2.getId());
//        assert Arrays.equals(data, bytes3);
    }


    //SM1 success
    @Test
    void testSm1() throws Exception {
        //key
        byte[] key = BytesOperate.base64DecodeData(device.getRandom(16));
        //iv
        byte[] iv = BytesOperate.base64DecodeData(device.getRandom(16));
        //SM1 ECB 内部
        byte[] encodeData4 = device.sm1InternalEncryptECB(1, data);
        byte[] decodeData4 = device.sm1InternalDecryptECB(1, encodeData4);
        assert Arrays.equals(data, decodeData4);

        //SM1 ECB 外部
        byte[] encodeData5 = device.sm1ExternalEncryptECB(key, data);
        byte[] decodeData5 = device.sm1ExternalDecryptECB(key, encodeData5);
        assert Arrays.equals(data, decodeData5);

//        //SM1 ECB 密钥句柄
//        SessionKey key3 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        byte[] bytes4 = device.sm1HandleEncryptECB(key3.getId(), data);
//        byte[] bytes5 = device.sm1HandleDecryptECB(key3.getId(), bytes4);
//        //释放密钥句柄
//        device.releaseSessionKey(key3.getId());
//        assert Arrays.equals(data, bytes5);


        //SM1 CBC 内部
        byte[] encodeData6 = device.sm1InternalEncryptCBC(1, iv, data);
        byte[] decodeData6 = device.sm1InternalDecryptCBC(1, iv, encodeData6);
        assert Arrays.equals(data, decodeData6);

        //SM1 CBC 外部
        byte[] encodeData7 = device.sm1ExternalEncryptCBC(key, iv, data);
        byte[] decodeData7 = device.sm1ExternalDecryptCBC(key, iv, encodeData7);
        assert Arrays.equals(data, decodeData7);

//        //SM1 CBC 密钥句柄
//        SessionKey key4 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        byte[] bytes6 = device.sm1HandleEncryptCBC(key4.getId(), iv, data);
//        byte[] bytes7 = device.sm1HandleDecryptCBC(key4.getId(), iv, bytes6);
//        //释放密钥句柄
//        device.releaseSessionKey(key4.getId());
//        assert Arrays.equals(data, bytes7);
    }


    //Sm4 批量 success
    @Test
    void testSm4Batch() throws Exception {
        //key
        byte[] key = BytesOperate.base64DecodeData(device.getRandom(16));
        //iv
        byte[] iv = BytesOperate.base64DecodeData(device.getRandom(16));

        List<byte[]> list = new ArrayList<>();
        list.add(data);
        list.add(data);
        list.add(data);

        //SM4 ECB 内部
        List<byte[]> encodeList = device.sm4InternalBatchEncryptECB(1, list);
        List<byte[]> decodeList = device.sm4InternalBatchDecryptECB(1, encodeList);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList.get(i));
        }

        //SM4 ECB 外部
        List<byte[]> encodeList1 = device.sm4ExternalBatchEncryptECB(key, list);
        List<byte[]> decodeList1 = device.sm4ExternalBatchDecryptECB(key, encodeList1);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList1.get(i));
        }

//        //SM4 ECB 密钥句柄
//        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        List<byte[]> encodeList2 = device.sm4HandleBatchEncryptECB(key1.getId(), list);
//        List<byte[]> decodeList2 = device.sm4HandleBatchDecryptECB(key1.getId(), encodeList2);
//        //释放密钥句柄
//        device.releaseSessionKey(key1.getId());
//        for (int i = 0; i < list.size(); i++) {
//            assert Arrays.equals(list.get(i), decodeList2.get(i));
//        }

        //SM4 CBC 内部
        List<byte[]> encodeList3 = device.sm4InternalBatchEncryptCBC(1, iv, list);
        List<byte[]> decodeList3 = device.sm4InternalBatchDecryptCBC(1, iv, encodeList3);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList3.get(i));
        }

        //SM4 CBC 外部
        List<byte[]> encodeList4 = device.sm4ExternalBatchEncryptCBC(key, iv, list);
        List<byte[]> decodeList4 = device.sm4ExternalBatchDecryptCBC(key, iv, encodeList4);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList4.get(i));
        }

//        //SM4 CBC 密钥句柄
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        List<byte[]> encodeList5 = device.sm4HandleBatchEncryptCBC(key2.getId(), iv, list);
//        List<byte[]> decodeList5 = device.sm4HandleBatchDecryptCBC(key2.getId(), iv, encodeList5);
//        //释放密钥句柄
//        device.releaseSessionKey(key2.getId());
//        for (int i = 0; i < list.size(); i++) {
//            assert Arrays.equals(list.get(i), decodeList5.get(i));
//        }


    }

    //SM1 批量 success
    @Test
    void testSm1Batch() throws Exception {
        //key
        byte[] key = BytesOperate.base64DecodeData(device.getRandom(16));
        //iv
        byte[] iv = BytesOperate.base64DecodeData(device.getRandom(16));

        List<byte[]> list = new ArrayList<>();
        list.add(data);
        list.add(data);
        list.add(data);

        //SM1 ECB 内部
        List<byte[]> encodeList = device.sm1InternalBatchEncryptECB(1, list);
        List<byte[]> decodeList = device.sm1InternalBatchDecryptECB(1, encodeList);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList.get(i));
        }

        //SM1 ECB 外部
        List<byte[]> encodeList1 = device.sm1ExternalBatchEncryptECB(key, list);
        List<byte[]> decodeList1 = device.sm1ExternalBatchDecryptECB(key, encodeList1);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList1.get(i));
        }

//        //SM1 ECB 密钥句柄
//        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        List<byte[]> encodeList2 = device.sm1HandleBatchEncryptECB(key1.getId(), list);
//        List<byte[]> decodeList2 = device.sm1HandleBatchDecryptECB(key1.getId(), encodeList2);
//        //释放密钥句柄
//        device.releaseSessionKey(key1.getId());
//        for (int i = 0; i < list.size(); i++) {
//            assert Arrays.equals(list.get(i), decodeList2.get(i));
//        }

        //SM1 CBC 内部
        List<byte[]> encodeList3 = device.sm1InternalBatchEncryptCBC(1, iv, list);
        List<byte[]> decodeList3 = device.sm1InternalBatchDecryptCBC(1, iv, encodeList3);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList3.get(i));
        }

        //SM1 CBC 外部
        List<byte[]> encodeList4 = device.sm1ExternalBatchEncryptCBC(key, iv, list);
        List<byte[]> decodeList4 = device.sm1ExternalBatchDecryptCBC(key, iv, encodeList4);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList4.get(i));
        }

//        //SM1 CBC 密钥句柄
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        List<byte[]> encodeList5 = device.sm1HandleBatchEncryptCBC(key2.getId(), iv, list);
//        List<byte[]> decodeList5 = device.sm1HandleBatchDecryptCBC(key2.getId(), iv, encodeList5);
//        //释放密钥句柄
//        device.releaseSessionKey(key2.getId());
//        for (int i = 0; i < list.size(); i++) {
//            assert Arrays.equals(list.get(i), decodeList5.get(i));
//        }

    }

    //MAC计算 success
    @Test
    void testMac() throws Exception {
        //key
        byte[] key = BytesOperate.base64DecodeData(device.getRandom(16));
        //iv
        byte[] iv = BytesOperate.base64DecodeData(device.getRandom(16));

        //SM4 内部
        byte[] mac = device.sm4InternalMac(1, iv, data);
        //SM4 外部
        byte[] mac1 = device.sm4ExternalMac(key, iv, data);

//        //SM4 密钥句柄
//        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        byte[] mac2 = device.sm4HandleMac(key1.getId(), iv, data);
//        //释放密钥句柄
//        device.releaseSessionKey(key1.getId());

        //SM1 内部
        byte[] mac3 = device.sm1InternalMac(1, iv, data);

        //SM1 外部
        byte[] mac4 = device.sm1ExternalMac(key, iv, data);

//        //SM1 密钥句柄
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        byte[] mac5 = device.sm1HandleMac(key2.getId(), iv, data);
//        //释放密钥句柄

    }

    //SM3-HMAC success
    @Test
    void testSm3HMAC() throws Exception {
        //key
        byte[] key = BytesOperate.base64DecodeData(device.getRandom(16));
        //iv
        byte[] iv = BytesOperate.base64DecodeData(device.getRandom(16));
        byte[] bytes = device.sm3Hmac(key, data);
        System.out.println(new String(bytes));
    }

    //
    //Hash
    @Test
    void testHash() throws Exception {

        byte[] userId = "1234567812345678".getBytes();
        //init
        device.sm3HashInit();

        //update
        device.sm3HashUpdate(data);
        device.sm3HashUpdate(data);

        //final
        byte[] bytes = device.sm3HashFinal();
        System.out.println("sm3 hash 分步结果:" + new String(bytes));

        byte[] bytes2 = device.sm3Hash(data);
        System.out.println("sm3 hash 一步结果:" + new String(bytes2));

        //生成Sm2密钥对
        SM2KeyPairStructure sm2KeyPairStructure = device.generateSM2KeyPair(1);
        //公钥
        byte[] pubKey = sm2KeyPairStructure.getPubKey();

        //init with pubKey
        device.sm3HashInitWithPubKey(pubKey, userId);

        //update
        device.sm3HashUpdate(data);
        device.sm3HashUpdate(data);

        //final
        byte[] bytes1 = device.sm3HashFinal();
        System.out.println("sm3 hash 带公钥 分步结果:" + new String(bytes1));

        byte[] bytes3 = device.sm3HashWithPubKey(pubKey, userId, data);
        System.out.println("sm3 hash 带公钥 一步结果:" + new String(bytes3));


    }


    //获取连接个数 success
    @Test
    void testGetConnectNum() throws Exception {
        int connectNum = device.getConnectCount();
        System.out.println(connectNum);
    }

    //endregion

    //region //SV独有

    // 根据别名获取 CA 证书个数 success
    @Test
    void testGetCACertCount() throws Exception {

        //qq
        int zzy = device.getCertCountByAltName("qq".getBytes());
        System.out.println(zzy);

        //证书链
        int certChain = device.getCertCountByAltName("证书链".getBytes());
        System.out.println(certChain);

    }

    // 根据别名获取 CA 证书 success
    @Test
    void testGetCACertByAltName() throws Exception {
        byte[] certByAltName = device.getCertByAltName("qq".getBytes(), 1);
        System.out.println(new String(certByAltName));

        byte[] certByAltName2 = device.getCertByAltName("证书链".getBytes(), 1);
        System.out.println(new String(certByAltName2));
    }


    //获取所有 CA 证书的别名 success
    @Test
    void testGetAllCACertAltName() throws Exception {
        CertAltNameTrustList certTrustListAltName = device.getCertTrustListAltName();
        System.out.println(new String(certTrustListAltName.getCertList()));
    }

    //验证证书有效性 success
    @Test
    void testVerifyCert() throws Exception {
        int i = device.validateCertificate(userCert);
        assert i == 0;
//        device.isCertificateRevoked(cert);
    }

    //验证证书有效性 ignore
    @Test
    @Ignore
    void testVerifyCert2() throws Exception {
        byte[] crlData = new byte[0];
        boolean certificateRevoked = device.isCertificateRevoked(userCert, crlData);
        assert !certificateRevoked;
    }

    //验证证书有效性 根证书/中间证书/用户证书
    @Test
    void testVerifyCert3() throws Exception {
        String userCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICUTCCAfigAwIBAgIJAOWoGwJCnci1MAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
                "DTIzMTAyNjA2MTM1M1oXDTI0MTAyNTA2MTM1M1owZzELMAkGA1UEBhMCQ04xETAP\n" +
                "BgNVBAgMCHNoYW5kb25nMQ4wDAYDVQQHDAVqaW5hbjENMAsGA1UECgwEc3phZjER\n" +
                "MA8GA1UECwwIc3phZl9zZWMxEzARBgNVBAMMCmNsb3VkX3Rlc3QwWTATBgcqhkjO\n" +
                "PQIBBggqgRzPVQGCLQNCAAS1UrlKVHMKsXi8eTiVwyjQZmZgNtJC/xjjkzY7JRRx\n" +
                "F2zHynLrfmGO/iDrW5ALLbn1ZSAcnrFnwW86NrjPfwXBo4GMMIGJMAwGA1UdEwEB\n" +
                "/wQCMAAwCwYDVR0PBAQDAgeAMCwGCWCGSAGG+EIBDQQfFh1HTUNlcnQub3JnIFNp\n" +
                "Z25lZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU5rtPV6byvsSfKgplsthW+xyMMqsw\n" +
                "HwYDVR0jBBgwFoAUf1peOwCEWSoPmL6hDm85lUMQTQcwCgYIKoEcz1UBg3UDRwAw\n" +
                "RAIgS53rXeeoF+IfatvsRc39cx3zXkJOTlszFYLitjpU1l8CIGnS8D9ntOxFZn5v\n" +
                "AFUSFI65In10ZTwsN5kK4UN/kxFx\n" +
                "-----END CERTIFICATE-----";

        String rootCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICIzCCAcigAwIBAgIJAKun/ZLoSXfeMAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
                "DTE5MTAyNDEyMzEzM1oXDTM5MDcxMTEyMzEzM1owZzELMAkGA1UEBhMCQ04xEDAO\n" +
                "BgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0hhaURpYW4xEzARBgNVBAoMCkdNQ2Vy\n" +
                "dC5vcmcxHzAdBgNVBAMMFkdNQ2VydCBHTSBSb290IENBIC0gMDEwWTATBgcqhkjO\n" +
                "PQIBBggqgRzPVQGCLQNCAASXWWtv+ifV7dJHqPNXwcmioh/48Wg3IuI+o11nLEOD\n" +
                "zljxL2yMxoQM6xfNJHuqadXXNZv3D2rml5Pk0W/tmfHEo10wWzAdBgNVHQ4EFgQU\n" +
                "f1peOwCEWSoPmL6hDm85lUMQTQcwHwYDVR0jBBgwFoAUf1peOwCEWSoPmL6hDm85\n" +
                "lUMQTQcwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwCgYIKoEcz1UBg3UDSQAw\n" +
                "RgIhAJ7AZAC0i+4OyfxDuvPIg0I7ZtqL2kII2f1syaIW4C6iAiEAlHuUu0TMrOAr\n" +
                "sU47scL1B9BhyEh5tbEjsKLHia3K0YU=\n" +
                "-----END CERTIFICATE-----";


//        String userCert = "-----BEGIN CERTIFICATE-----\r\n MIIEMjCCA9WgAwIBAgIIaeIA0AAnL0IwDAYIKoEcz1UBg3UFADCBgjELMAkGA1UEBhMCQ04xDzANBgNVBAgMBll1bm5hbjEQMA4GA1UEBwwHS3VubWluZzENMAsGA1UECgwEeW5jYTEuMCwGA1UECwwlWXVubmFuIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IENlbnRyZTERMA8GA1UEAwwIWU5DQV9TTTIwHhcNMjIwOTI5MDY0OTAwWhcNMjMwOTI5MDY0OTAwWjBpMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5YyX5Lqs5biCMRIwEAYDVQQHDAnluILovpbljLoxDzANBgNVBAUMBjY4NDk2NjEhMB8GA1UEAwwY5rWq5r2u5oC76ZuG5rWL6K+V5p2O5biFMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEw+dcbcbwvHq6easfBiE5QR/eY/2NOUAmPYtjvab8ykAlybhrBkS7LDqAledS4ziFI+oJPwVL1BnoeW5i+88jQaOCAkkwggJFMAwGA1UdEwQFMAMBAQAwKgYDVR0lAQH/BCAwHgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBDALBgNVHQ8EBAMCAMAwGgYEKgUdAQQSOTExMTAxMDYzOTk0MTQwMVhHMB8GA1UdIwQYMBaAFDjDC6Z+GXwOzw0+ouzFH2r8ubTgMIGoBgNVHR8EgaAwgZ0wgZqggZeggZSGgZFsZGFwOi8vc2xkYXAueXVubmFuY2EubmV0L0NOPVlOQ0FfU00yLENOPVlOQ0FfU00yLCBPVT1DUkxEaXN0cmlidXRlUG9pbnRzLCBvPXluY2E/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdGNsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIGiBggrBgEFBQcBAQSBlTCBkjCBjwYIKwYBBQUHMAKGgYJsZGFwOi8vc2xkYXAueXVubmFuY2EubmV0L0NOPVlOQ0FfU00yLENOPVlOQ0FfU00yLCBTVD1jQUNlcnRpZmljYXRlcywgbz15bmNhP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MB0GA1UdDgQWBBQOMN0MNeXMW3zGH3mnPaMcdzjiaTBQBgNVHSAESTBHMEUGCCqBHM9VCAEBMDkwNwYIKwYBBQUHAgEWK2h0dHA6Ly93d3cueXVubmFuY2EubmV0Lz9waWNkb3duL2lkLzIzLmh0bWwwDAYIKoEcz1UBg3UFAANJADBGAiEAjg9DulijKASqJxQZlEl8gJhcgXBahzIsXgJHJfr4T6oCIQCzxOdUFY5Et3sF5lqM8WMhWpBJnsTIYj00+WuYroYWpg==\r\n-----END CERTIFICATE-----";
//        String rootCert = "-----BEGIN CERTIFICATE-----\r\n" + "MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG\r\n"
//                + "EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw\r\n" + "MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO\r\n"
//                + "UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\r\n" + "MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT\r\n"
//                + "V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti\r\n" + "W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ\r\n"
//                + "MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b\r\n" + "53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI\r\n" + "pDoiVhsLwg==\r\n"
//                + "-----END CERTIFICATE-----\r\n" + "";
//
//        String caCert = "-----BEGIN CERTIFICATE-----\r\n" + "MIIC2DCCAnugAwIBAgIQV7TuB2YcI/6qDe1ASX7IyzAMBggqgRzPVQGDdQUAMC4x\r\n"
//                + "CzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVOUkNBQzEPMA0GA1UEAwwGUk9PVENBMB4X\r\n" + "DTE0MDIxMTA5Mzc0OVoXDTM0MDIwNjA5Mzc0OVowgYIxCzAJBgNVBAYTAkNOMQ8w\r\n"
//                + "DQYDVQQIDAZZdW5uYW4xEDAOBgNVBAcMB0t1bm1pbmcxDTALBgNVBAoMBHluY2Ex\r\n" + "LjAsBgNVBAsMJVl1bm5hbiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBDZW50cmUx\r\n"
//                + "ETAPBgNVBAMMCFlOQ0FfU00yMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAELCV0\r\n" + "NY0gBgUE2mGQQchmFug20hxd+gC6MYW3M40uQ4iKDWs+n3EG6nc+gywL+vxFVPdH\r\n"
//                + "/RXLRh98xOarhF0yj6OCASIwggEeMB8GA1UdIwQYMBaAFEwysZfZMxvEpgXBxuWL\r\n" + "Ylvwl3ZYMA8GA1UdEwEB/wQFMAMBAf8wgboGA1UdHwSBsjCBrzBBoD+gPaQ7MDkx\r\n"
//                + "CzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVOUkNBQzEMMAoGA1UECwwDQVJMMQwwCgYD\r\n" + "VQQDDANhcmwwKqAooCaGJGh0dHA6Ly93d3cucm9vdGNhLmdvdi5jbi9hcmwvYXJs\r\n"
//                + "LmNybDA+oDygOoY4bGRhcDovL2xkYXAucm9vdGNhLmdvdi5jbjozODkvQ049YXJs\r\n" + "LE9VPUFSTCxPPU5SQ0FDLEM9Q04wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQ4\r\n"
//                + "wwumfhl8Ds8NPqLsxR9q/Lm04DAMBggqgRzPVQGDdQUAA0kAMEYCIQDfw9cTuNlP\r\n" + "VV/Ou4B9P9ACqtPmCdd57z2guDdmrVnyYgIhAOfB9RKct0/DCQwbqtYSZUfMAkWN\r\n"
//                + "8qPKrD6MddSsfi1i\r\n" + "-----END CERTIFICATE-----\r\n" + "";

        boolean b = device.validateCertificate(rootCert, null, userCert);
        System.out.println("验证结果 " + b);
        assert b;
    }


    //获取证书信息 success
    @Test
    void testGetCertInfo() throws Exception {
        byte[] cert = FileUtil.readBytes(userCertFileSM2);
        for (int i = 1; i < 11; i++) {
            if (3 == i || 4 == i || 6 == i || 9 == i || 10 == i) {
                continue;
            }
            byte[] certInfo = device.getCertInfo(cert, i);
            System.out.println(new String(certInfo));
        }

//        byte[] certInfo = device.getCertInfo(cert, 8);
//        SM2PublicKey sm2PublicKey = new SM2PublicKey(certInfo);
//        System.out.println(sm2PublicKey);
    }

    // 根据 OID 获取证书信息 success
    @Test
    void testGetCertInfoByOid() throws Exception {
        //region 证书信息 OID
        List<byte[]> bytes = new ArrayList<>();
        //将上面注释中的全部添加进来
        bytes.add("2.5.29.9".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.14".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.16".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.17".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.18".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.19".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.20".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.21".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.22".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.23".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.24".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.27".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.28".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.29".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.30".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.31".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.32".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.33".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.35".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.36".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.37".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.46".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.54".getBytes(StandardCharsets.UTF_8));
        bytes.add("1.3.6.1.5.5.7.1.1".getBytes(StandardCharsets.UTF_8));
        bytes.add("1.3.6.1.5.5.7.1.11".getBytes(StandardCharsets.UTF_8));
        bytes.add("1.3.6.1.5.5.7.1.12".getBytes(StandardCharsets.UTF_8));
        bytes.add("1.3.6.1.5.5.7.1.2".getBytes(StandardCharsets.UTF_8));
        bytes.add("1.3.6.1.5.5.7.1.3".getBytes(StandardCharsets.UTF_8));
        bytes.add("1.3.6.1.5.5.7.1.4".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.56".getBytes(StandardCharsets.UTF_8));
        bytes.add("2.5.29.55".getBytes(StandardCharsets.UTF_8));

        //endregion

        for (byte[] b : bytes) {
            byte[] certInfoByOid = device.getCertInfoByOid(userCert, b);
            System.out.println(new String(certInfoByOid));
        }

    }

    //获取设备证书 success
    @Test
    void testGetDeviceCert() throws Exception {
        byte[] deviceCert = device.getServerCert();
        System.out.println(new String(deviceCert));
        byte[] serverCertByUsage = device.getServerCertByUsage(1);
        System.out.println("加密证书:" + new String(serverCertByUsage));
        byte[] serverCertByUsage1 = device.getServerCertByUsage(2);
        System.out.println("签名证书:" + new String(serverCertByUsage1));
    }

    //获取应用实体信息 success
    @Test
    void testGetAppEntityInfo() throws Exception {
        AFSvCryptoInstance instance = device.getInstance("zzyzzy");
        System.out.println(instance);
    }

    //根据证书的 DN 信息获取 CA 证书 颁发者信息 success
    @Test
    void testGetCACertByDN() throws Exception {
        byte[] dn = "C=CN,ST=Beijing,L=HaiDian,O=GMCert.org,CN=GMCert GM Root CA - 01".getBytes();
        byte[] caCertByDN = device.getCaCertByDn(dn);
        System.out.println(new String(caCertByDN));
    }

    //获取应用实体证书数据 success
    @Test
    void testGetAppEntityCert() throws Exception {
        String policyName = "zzyzzy";
        byte[] signCertByPolicyName = device.getSignCertByPolicyName(policyName);
        System.out.println(new String(signCertByPolicyName));
    }


    //获取证书的OCSP地址 success
    @Test
    void testGetOCSPURL() throws Exception {
        byte[] cert = FileUtil.readBytes(userCertFileSM2);
        byte[] ocspURL = device.getOcspUrl(cert);
        System.out.println(new String(ocspURL));
    }


    //PKCS7 签名信息编码 解码 验证 success
    @Test
    void testPKCS7() throws Exception {
        //私钥
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(getPriKey()).to256();
        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2PrivateKey);
        byte[] encoded = sm2PrivateKeyStructure.toASN1Primitive().getEncoded("DER");
        encoded = Base64.encode(encoded);
        String s = new String(encoded);
        System.out.println(s);
        byte[] bytes2 = s.getBytes();
        //签名证书
         byte[] cert = deviceCert;


        //签名信息编码
        byte[] bytes = device.encodeSignedDataForSM2(encoded, cert, data);
        System.out.println("第一次签名信息编码,不带原文" + new String(bytes));
        byte[] bytes1 = device.encodeSignedDataForSM2(true, encoded, cert, data);
        System.out.println("第二次签名信息编码,带原文" + new String(bytes1));


        //签名信息解码
        AFSM2DecodeSignedData afsm2DecodeSignedData = device.decodeSignedDataForSM2(bytes);
        System.out.println("第一次签名信息解码,不带原文" + afsm2DecodeSignedData);
        AFSM2DecodeSignedData afsm2DecodeSignedData1 = device.decodeSignedDataForSM2(bytes1);
        System.out.println("第二次签名信息解码,带原文" + afsm2DecodeSignedData1);

        //签名信息验证
        try {
            boolean b = device.verifySignedDataForSM2(bytes, null);
            System.out.println("第一次签名信息验证,不带原文" + b);
        } catch (IllegalArgumentException e) {
            System.out.println("超时==============继续重连后执行下面功能");
        }

        boolean b1 = device.verifySignedDataForSM2(bytes1, null);
        System.out.println("第二次签名信息验证,带原文" + b1);

    }

    //PKCS7 数字信封编码 解码 success
    @Test
    void testPKCS7EnvelopedData() throws Exception {

        //私钥
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(getPriKey()).to256();
        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2PrivateKey);
        byte[] encoded = sm2PrivateKeyStructure.toASN1Primitive().getEncoded("DER");
        encoded = Base64.encode(encoded);

        //对称密钥
        byte[] key = "1234567890abcdef".getBytes();
        //签名证书
        byte[] cert = deviceCert;
        //加密证书
        byte[] encCert = deviceCert;

        //数字信封编码
        byte[] bytes = device.encodeEnvelopedDataForSM2(encoded, key, cert, encCert, key);
        System.out.println("第一次数字信封编码" + new String(bytes));

        //数字信封解码
        AFPkcs7DecodeData afPkcs7DecodeData = device.decodeEnvelopedDataForSM2(encoded, bytes);
        System.out.println("第一次数字信封解码" + afPkcs7DecodeData);


    }

    @Test
    void test111() {
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(getPriKey());
        System.out.println(sm2PrivateKey);
    }

    //获取设备私钥 0018
    private byte[] getPriKey() {
        byte[] bytes = FileUtil.readBytes(userCertPrivateKeyPath);
        byte[] decode = Base64.decode(bytes);
        //删除前132个字节
        byte[] result = Arrays.copyOfRange(decode, 132, decode.length);
//        //保留前4个字节和后32个字节
//        byte[] result2 = new byte[36];
//        System.arraycopy(decode, 0, result2, 0, 4);
//        System.arraycopy(decode, decode.length - 32, result2, 4, 32);
//        result = result2;
        //base64 编码为字符串
        byte[] encode = Base64.encode(result);
        return result;
    }


    //endregion

    //region//======>http Request

    //根据密钥索引产生证书请求
    @Test
    void testGetCSRByIndex() throws Exception {
        CsrRequest csrRequest = new CsrRequest("cn", "sd", "jn", "szaf", "szaf", "zzyzzy", "zzypersonally@gmail.com");
        String csrByIndex = device.getCSRByIndex(5, csrRequest);
        System.out.println("CSR:" + csrByIndex);
    }

    //根据密钥索引导入证书
    @Test
    void testImportCertByIndex() throws Exception {
        String signCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICaDCCAg+gAwIBAgIJAOWoGwJCnb1tMAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
                "DTIzMDgxNTAyMjA1M1oXDTI0MDgxNDAyMjA1M1owfjELMAkGA1UEBgwCY24xCzAJ\n" +
                "BgNVBAgMAnNkMQswCQYDVQQHDAJqbjENMAsGA1UECgwEc3phZjENMAsGA1UECwwE\n" +
                "c3phZjEPMA0GA1UEAwwGenp5enp5MSYwJAYJKoZIhvcNAQkBFhd6enlwZXJzb25h\n" +
                "bGx5QGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABGJ2MzrbqDcI\n" +
                "eCq8pslihUoaBkRxKgZOFYpsJrRMobXsEt2UJm9edCrlVh0WW0QVypZyIfjrcm+O\n" +
                "GEoDGVi9AdOjgYwwgYkwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwLAYJYIZI\n" +
                "AYb4QgENBB8WHUdNQ2VydC5vcmcgU2lnbmVkIENlcnRpZmljYXRlMB0GA1UdDgQW\n" +
                "BBT6Nvj4g2PtYe7lAsN7I9ZbjpRQnjAfBgNVHSMEGDAWgBR/Wl47AIRZKg+YvqEO\n" +
                "bzmVQxBNBzAKBggqgRzPVQGDdQNHADBEAiA8w82kjmSOo8RP01X60TI1R7Nu5j8M\n" +
                "zLib3ZryuAHFpQIgAXaO7qvAQ9qhosVpvlbhx4+c8SSUuR+ZjKY1Ubethx4=\n" +
                "-----END CERTIFICATE-----\n";
        String encCert = "";
        String encPriKey = "";

        device.importCertByIndex(5, signCert, encCert, encPriKey);
    }

    //根据密钥索引获取证书
    @Test
    void testGetCertByIndex() throws Exception {
        Map<String, String> certMap = device.getCertByIndex(5);
        System.out.println("cert:" + certMap);
    }

    //删除密钥
    @Test
    void testDeleteKey() throws Exception {
        device.deleteKey(5);
    }
    //endregion


    //根据网站 签发的证书和私钥 签名一条信息 带Z值
    @Test
    void test3242() throws Exception {
        String keyStr = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIPpPJ23h6tP1wQfjZ3Ct4wpR4nqNhpDYKwThwTB7Mq0ToAoGCCqBHM9V\n" +
                "AYItoUQDQgAEtVK5SlRzCrF4vHk4lcMo0GZmYDbSQv8Y45M2OyUUcRdsx8py635h\n" +
                "jv4g61uQCy259WUgHJ6xZ8FvOja4z38FwQ==\n" +
                "-----END EC PRIVATE KEY-----\n";

        String base64Key = "AAEAAPpPJ23h6tP1wQfjZ3Ct4wpR4nqNhpDYKwThwTB7Mq0T";

        String certStr = "-----BEGIN CERTIFICATE-----\n" +
                "MIICUTCCAfigAwIBAgIJAOWoGwJCnci1MAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
                "DTIzMTAyNjA2MTM1M1oXDTI0MTAyNTA2MTM1M1owZzELMAkGA1UEBhMCQ04xETAP\n" +
                "BgNVBAgMCHNoYW5kb25nMQ4wDAYDVQQHDAVqaW5hbjENMAsGA1UECgwEc3phZjER\n" +
                "MA8GA1UECwwIc3phZl9zZWMxEzARBgNVBAMMCmNsb3VkX3Rlc3QwWTATBgcqhkjO\n" +
                "PQIBBggqgRzPVQGCLQNCAAS1UrlKVHMKsXi8eTiVwyjQZmZgNtJC/xjjkzY7JRRx\n" +
                "F2zHynLrfmGO/iDrW5ALLbn1ZSAcnrFnwW86NrjPfwXBo4GMMIGJMAwGA1UdEwEB\n" +
                "/wQCMAAwCwYDVR0PBAQDAgeAMCwGCWCGSAGG+EIBDQQfFh1HTUNlcnQub3JnIFNp\n" +
                "Z25lZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU5rtPV6byvsSfKgplsthW+xyMMqsw\n" +
                "HwYDVR0jBBgwFoAUf1peOwCEWSoPmL6hDm85lUMQTQcwCgYIKoEcz1UBg3UDRwAw\n" +
                "RAIgS53rXeeoF+IfatvsRc39cx3zXkJOTlszFYLitjpU1l8CIGnS8D9ntOxFZn5v\n" +
                "AFUSFI65In10ZTwsN5kK4UN/kxFx\n" +
                "-----END CERTIFICATE-----";

        System.out.println(certStr);

        byte[] key0018 = cn.hutool.core.codec.Base64.decode(base64Key);
        System.out.println(key0018.length);

        byte[] sub = ArrayUtil.sub(key0018, 4, 36);
        System.out.println("sub len " + sub.length);
        byte[] bytes = ArrayUtil.addAll(BytesOperate.int2bytes(256), new byte[32], sub);

        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(bytes);
        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2PrivateKey);
        byte[] encoded = sm2PrivateKeyStructure.toASN1Primitive().getEncoded();
        byte[] bytes2 = BytesOperate.base64EncodeData(encoded);

        byte[] bytes1 = device.sm2SignatureByCertificate(bytes2, "af/密码云平台测试".getBytes(StandardCharsets.UTF_8), certStr.getBytes(StandardCharsets.UTF_8));

//        boolean b2 = device.sm2VerifyByCertificate(certStr.getBytes(), "af/密码云平台测试".getBytes(StandardCharsets.UTF_8), bytes1);
//        System.out.println(b2);

        SM2PublicKey sm2PublicKey = AFSVDevice.parseSM2PublicKeyFromCert(certStr.getBytes());
        byte[] encode = sm2PublicKey.encode();
        data = new SM3Impl().SM3HashWithPublicKey256("af/密码云平台测试".getBytes(StandardCharsets.UTF_8), sm2PublicKey, ConstantNumber.DEFAULT_USER_ID.getBytes());
        System.out.println("消息摘要长度:"+data.length);
        String encode1 = cn.hutool.core.codec.Base64.encode(data);
        System.out.println(encode1);
        boolean b = device.sm2Verify(encode, "", data, bytes1);
        System.out.println(b);


    }

    //文件签名
    @Test
    void test213412()throws  Exception {
//        String keyStr = "-----BEGIN EC PRIVATE KEY-----\n" +
//                "MHcCAQEEIPpPJ23h6tP1wQfjZ3Ct4wpR4nqNhpDYKwThwTB7Mq0ToAoGCCqBHM9V\n" +
//                "AYItoUQDQgAEtVK5SlRzCrF4vHk4lcMo0GZmYDbSQv8Y45M2OyUUcRdsx8py635h\n" +
//                "jv4g61uQCy259WUgHJ6xZ8FvOja4z38FwQ==\n" +
//                "-----END EC PRIVATE KEY-----\n";
//
//        String base64Key = "AAEAAPpPJ23h6tP1wQfjZ3Ct4wpR4nqNhpDYKwThwTB7Mq0T";
//
//        String certStr = "-----BEGIN CERTIFICATE-----\n" +
//                "MIICUTCCAfigAwIBAgIJAOWoGwJCnci1MAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
//                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
//                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
//                "DTIzMTAyNjA2MTM1M1oXDTI0MTAyNTA2MTM1M1owZzELMAkGA1UEBhMCQ04xETAP\n" +
//                "BgNVBAgMCHNoYW5kb25nMQ4wDAYDVQQHDAVqaW5hbjENMAsGA1UECgwEc3phZjER\n" +
//                "MA8GA1UECwwIc3phZl9zZWMxEzARBgNVBAMMCmNsb3VkX3Rlc3QwWTATBgcqhkjO\n" +
//                "PQIBBggqgRzPVQGCLQNCAAS1UrlKVHMKsXi8eTiVwyjQZmZgNtJC/xjjkzY7JRRx\n" +
//                "F2zHynLrfmGO/iDrW5ALLbn1ZSAcnrFnwW86NrjPfwXBo4GMMIGJMAwGA1UdEwEB\n" +
//                "/wQCMAAwCwYDVR0PBAQDAgeAMCwGCWCGSAGG+EIBDQQfFh1HTUNlcnQub3JnIFNp\n" +
//                "Z25lZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU5rtPV6byvsSfKgplsthW+xyMMqsw\n" +
//                "HwYDVR0jBBgwFoAUf1peOwCEWSoPmL6hDm85lUMQTQcwCgYIKoEcz1UBg3UDRwAw\n" +
//                "RAIgS53rXeeoF+IfatvsRc39cx3zXkJOTlszFYLitjpU1l8CIGnS8D9ntOxFZn5v\n" +
//                "AFUSFI65In10ZTwsN5kK4UN/kxFx\n" +
//                "-----END CERTIFICATE-----";
//
//
//        byte[] key0018 = cn.hutool.core.codec.Base64.decode(base64Key);
//        System.out.println(key0018.length);
//
//        byte[] sub = ArrayUtil.sub(key0018, 4, 36);
//        System.out.println("sub len " + sub.length);
//        byte[] bytes = ArrayUtil.addAll(BytesOperate.int2bytes(256), new byte[32], sub);
//
//        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(bytes);
//        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2PrivateKey);
//        byte[] encoded = sm2PrivateKeyStructure.toASN1Primitive().getEncoded();
//        byte[] bytes2 = BytesOperate.base64EncodeData(encoded);
//
//
//        byte[] bytes1 = device.sm2SignFileByCertificate(bytes2, "C:\\Users\\zzype\\Desktop\\1.txt".getBytes(), certStr.getBytes());
//
//        boolean b = device.sm2VerifyFileByCertificate(certStr.getBytes(), "C:\\Users\\zzype\\Desktop\\1.txt".getBytes(), bytes1);
//        System.out.println();
//
//
//        System.out.println(cn.hutool.core.codec.Base64.encode(bytes1));


        String s = "-----BEGIN CERTIFICATE-----\n" +
                "MIICYjCCAgigAwIBAgIJAOWoGwJCnclbMAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
                "DTIzMTAzMTAzNDYxMFoXDTI0MTAzMDAzNDYxMFowdzELMAkGA1UEBgwCQ04xCzAJ\n" +
                "BgNVBAgMAlNEMQswCQYDVQQHDAJKTjENMAsGA1UECgwEU1pBRjERMA8GA1UECwwI\n" +
                "U1pBRl9UU0ExDDAKBgNVBAMMA1paWTEeMBwGCSqGSIb3DQEJARYPMTIzNDU2NzhA\n" +
                "cXEuY29tMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE4mtOrgNr9lCFYCnGFdra\n" +
                "k8fLDS3ovw4DoGsNXMb9ovgBlWdcDe97muTMv3wTjn6gq2tSfheYY4OI62kOOBfV\n" +
                "e6OBjDCBiTAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDAsBglghkgBhvhCAQ0E\n" +
                "HxYdR01DZXJ0Lm9yZyBTaWduZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFKwzSx0F\n" +
                "XSIdyM3/tJt0HqrFNgZTMB8GA1UdIwQYMBaAFH9aXjsAhFkqD5i+oQ5vOZVDEE0H\n" +
                "MAoGCCqBHM9VAYN1A0gAMEUCIGeGstosq3fJqRUxjZCbYx9fUSBib+WhfESr5WPv\n" +
                "Eee0AiEA76uKcGOkTmzTtW65LzpOknY5jSMy7hkRlQF7Femxn0g=\n" +
                "-----END CERTIFICATE-----";

        //去除换行
        s = s.replaceAll("\n", "");

        System.out.println(s);

    }





}