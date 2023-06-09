package com.af.device.impl;

import cn.hutool.core.io.FileUtil;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.device.AFDeviceFactory;
import com.af.device.DeviceInfo;
import com.af.struct.signAndVerify.AFPkcs7DecodeData;
import com.af.struct.signAndVerify.AFSvCryptoInstance;
import com.af.struct.signAndVerify.CertAltNameTrustList;
import com.af.struct.signAndVerify.RSA.RSAKeyPairStructure;
import com.af.struct.signAndVerify.sm2.SM2KeyPairStructure;
import com.af.struct.signAndVerify.sm2.SM2PrivateKeyStructure;
import com.af.utils.base64.Base64;
import jdk.nashorn.internal.ir.annotations.Ignore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;


class

AFSVDeviceTest {

    //region //初始化数据

    //日志
    static Logger logger = Logger.getLogger("AFSVDeviceTest");

    //        static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.1.232", 6001, "abcd1234");
    static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.10.40", 8011, "abcd1234");
    static byte[] data = "1234567890abcdef".getBytes();

    //证书文件路径
    static String userCertFileSM2 = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\testCert.cer";
    static String userCertFileRSA = "src\\test\\resources\\user.crt";
    static String deviceCertFile = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\device.cer";
    static String deviceEncCertFile = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\deviceEnc.cer";

    //证书文件
    static byte[] cert = FileUtil.readBytes(userCertFileSM2);
    static byte[] deviceCert = FileUtil.readBytes(deviceCertFile);
    static byte[] deviceEncCert = FileUtil.readBytes(deviceEncCertFile);

    //签名文件路径
    static byte[] fileName = "src\\test\\resources\\singFile.txt".getBytes(StandardCharsets.UTF_8);


    //SM2公钥  base64
    static String sm2PubKeyDataBase64 = "AAEAAIHQcN4xEd3myIvZRFdf+M2jtBbh3Ik8aON7J55A91AAApm2+TtovD7Pl5dSQ/5RFbQcZQk9pm3orfKkgRYp/kY=";
    //SM2私钥 base64
    static String sm2PrvKeyDataBase64 = "AAEAAEnKCb0n669m/apkWqAOfz6MsQZD68yIShAbmdQ5MMDK";


    //endregion


    @AfterAll
    static void tearDown() throws Exception {
        logger.info("发送关闭连接请求");
        device.close(AFSVDevice.client);
        logger.info("已经关闭连接");
    }


    //region //与HSM共有

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
        byte[] random = device.getRandom(5);
        System.out.println(Arrays.toString(random));
    }

//    //导出公钥信息
//    @Test
//    void testGetPublicKey() throws Exception {
//        //RSA签名
//        byte[] rsaPublicKey = device.getRSAPublicKey(1, 0);
//        System.out.println("RSA签名公钥:" + new String(rsaPublicKey));
//        //RSA加密
//        byte[] rsaPublicKey2 = device.getRSAPublicKey(1, 1);
//        System.out.println("RSA加密公钥:" + new String(rsaPublicKey2));
//        //SM2 签名
//        byte[] sm2PublicKey = device.getSm2PublicKey(1, 0);
//        System.out.println("SM2签名公钥:" + new String(sm2PublicKey));
//        //SM2加密
//        byte[] sm2PublicKey2 = device.getSm2PublicKey(1, 1);
//        System.out.println("SM2加密公钥:" + new String(sm2PublicKey2));
//    }

    //导出公钥 success
    @Test
    void testExportPublicKey() throws Exception {
        //SM2
        byte[] sm2EncryptPublicKey = device.getSM2EncryptPublicKey(1);
        System.out.println("SM2加密公钥:" + new String(sm2EncryptPublicKey));
        byte[] sm2SignPublicKey = device.getSM2SignPublicKey(1);
        System.out.println("SM2签名公钥:" + new String(sm2SignPublicKey));

        //RSA
        byte[] rsaSignPublicKey = device.getRSASignPublicKey(1);
        System.out.println("RSA签名公钥:" + new String(rsaSignPublicKey));
        byte[] rsaEncPublicKey = device.getRSAEncPublicKey(1);
        System.out.println("RSA加密公钥:" + new String(rsaEncPublicKey));

    }

    //生成密钥对
    @Test
    void testGenerateKeyPair() throws Exception {
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


//    //RSA 操作
//    @Test
//    void testRSA() throws Exception {
//
//        //RSA 内部签名验签
//        byte[] bytes = device.rsaSignature(1, data);
//        boolean b = device.rsaVerify(1, data, bytes);
//
//        //RSA 外部签名验签
//        RSAKeyPair rsaKeyPair = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
//        byte[] bytes1 = device.rsaSignature(rsaKeyPair.getPriKey().encode(), data);
//        boolean b1 = device.rsaVerify(rsaKeyPair.getPubKey().encode(), data, bytes1);
//
//        //RSA内部密钥加解密
//        byte[] bytes2 = device.rsaEncrypt(1, data);
//        byte[] bytes3 = device.rsaDecrypt(1, bytes2);
//        assert Arrays.equals(data, bytes3);
//
//        //RSA 外部密钥加解密
//        byte[] bytes4 = device.rsaEncrypt(rsaKeyPair.getPubKey().encode(), data);
//        byte[] bytes5 = device.rsaDecrypt(rsaKeyPair.getPriKey().encode(), bytes4);
//        assert Arrays.equals(data, bytes5);
//
//    }
//
//    //SM2 操作
//    @Test
//    void testSM2() throws Exception {
//        //SM2 内部签名验签
//        byte[] bytes = device.sm2Signature(1, data);
//        boolean b = device.sm2Verify(1, data, bytes);
//        assert b;
//
//        //SM2 外部签名验签
//        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(0);
//        byte[] bytes1 = device.sm2Signature(sm2KeyPair.getPriKey().encode(), data);
//        boolean b1 = device.sm2VerifyByPublicKey(sm2KeyPair.getPubKey().encode(), data, bytes1);
//        assert b1;
//
//        //SM2内部密钥加解密
//        byte[] bytes2 = device.sm2Encrypt(1, data);
//        byte[] bytes3 = device.sm2Decrypt(1, bytes2);
//        assert Arrays.equals(data, bytes3);
//
//        //SM2 外部密钥加解密
//        SM2KeyPair sm2KeyPair1 = device.generateSM2KeyPair(1);
//        byte[] bytes4 = device.sm2Encrypt(sm2KeyPair1.getPubKey().encode(), data);
//        byte[] bytes5 = device.sm2Decrypt(sm2KeyPair1.getPriKey().encode(), bytes4);
//        assert Arrays.equals(data, bytes5);
//
//
//    }

    //SM4
    @Test
    void testSm4() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        //iv
        byte[] iv = device.getRandom(16);

        //SM4 ECB 内部
        byte[] encodeData = device.sm4InternalEncryptECB(1, data);
        byte[] decodeData = device.sm4InternalDecryptECB(1, encodeData);
        assert Arrays.equals(data, decodeData);

        //SM4 ECB 外部
        byte[] encodeData1 = device.sm4ExternalEncryptECB(key, data);
        byte[] decodeData1 = device.sm4ExternalDecryptECB(key, encodeData1);
        assert Arrays.equals(data, decodeData1);

//        //SM4 ECB 密钥句柄
//        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
//        byte[] bytes = device.sm4HandleEncryptECB(key1.getId(), data);
//        byte[] bytes1 = device.sm4HandleDecryptECB(key1.getId(), bytes);
//        //释放
//        device.releaseSessionKey(key1.getId());
//        assert Arrays.equals(data, bytes1);

        //SM4 CBC 内部
        byte[] encodeData2 = device.sm4InternalEncryptCBC(1, iv, data);
        byte[] decodeData2 = device.sm4InternalDecryptCBC(1, iv, encodeData2);
        assert Arrays.equals(data, decodeData2);

        //SM4 CBC 外部
        byte[] encodeData3 = device.sm4ExternalEncryptCBC(key, iv, data);
        byte[] decodeData3 = device.sm4ExternalDecryptCBC(key, iv, encodeData3);
        assert Arrays.equals(data, decodeData3);

//        //SM4 CBC 密钥句柄
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
//        byte[] bytes2 = device.sm4HandleEncryptCBC(key2.getId(), iv, data);
//        byte[] bytes3 = device.sm4HandleDecryptCBC(key2.getId(), iv, bytes2);
//        //释放密钥句柄
//        device.releaseSessionKey(key2.getId());
//        assert Arrays.equals(data, bytes3);


    }

    //SM1
    @Test
    void testSm1() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        //iv
        byte[] iv = device.getRandom(16);
        //SM1 ECB 内部
        byte[] encodeData4 = device.sm1InternalEncryptECB(1, data);
        byte[] decodeData4 = device.sm1InternalDecryptECB(1, encodeData4);
        assert Arrays.equals(data, decodeData4);

        //SM1 ECB 外部
        byte[] encodeData5 = device.sm1ExternalEncryptECB(key, data);
        byte[] decodeData5 = device.sm1ExternalDecryptECB(key, encodeData5);
        assert Arrays.equals(data, decodeData5);

//        //SM1 ECB 密钥句柄
//        SessionKey key3 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
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
//        SessionKey key4 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
//        byte[] bytes6 = device.sm1HandleEncryptCBC(key4.getId(), iv, data);
//        byte[] bytes7 = device.sm1HandleDecryptCBC(key4.getId(), iv, bytes6);
//        //释放密钥句柄
//        device.releaseSessionKey(key4.getId());
//        assert Arrays.equals(data, bytes7);
    }


    //Sm4 批量
    @Test
    void testSm4Batch() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        //iv
        byte[] iv = device.getRandom(16);

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
//        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
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
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
//        List<byte[]> encodeList5 = device.sm4HandleBatchEncryptCBC(key2.getId(), iv, list);
//        List<byte[]> decodeList5 = device.sm4HandleBatchDecryptCBC(key2.getId(), iv, encodeList5);
//        //释放密钥句柄
//        device.releaseSessionKey(key2.getId());
//        for (int i = 0; i < list.size(); i++) {
//            assert Arrays.equals(list.get(i), decodeList5.get(i));
//        }


    }

    //SM1 批量
    @Test
    void testSm1Batch() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        //iv
        byte[] iv = device.getRandom(16);

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
//        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
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
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
//        List<byte[]> encodeList5 = device.sm1HandleBatchEncryptCBC(key2.getId(), iv, list);
//        List<byte[]> decodeList5 = device.sm1HandleBatchDecryptCBC(key2.getId(), iv, encodeList5);
//        //释放密钥句柄
//        device.releaseSessionKey(key2.getId());
//        for (int i = 0; i < list.size(); i++) {
//            assert Arrays.equals(list.get(i), decodeList5.get(i));
//        }

    }

    //MAC计算
    @Test
    void testMac() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        //iv
        byte[] iv = device.getRandom(16);

        //SM4 内部
        byte[] mac = device.sm4InternalMac(1, iv, data);

        //SM4 外部
        byte[] mac1 = device.sm4ExternalMac(key, iv, data);

//        //SM4 密钥句柄
//        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
//        byte[] mac2 = device.sm4HandleMac(key1.getId(), iv, data);
//        //释放密钥句柄
//        device.releaseSessionKey(key1.getId());

        //SM1 内部
        byte[] mac3 = device.sm1InternalMac(1, iv, data);

        //SM1 外部
        byte[] mac4 = device.sm1ExternalMac(key, iv, data);

//        //SM1 密钥句柄
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
//        byte[] mac5 = device.sm1HandleMac(key2.getId(), iv, data);
//        //释放密钥句柄

    }

    //SM3-HMAC
    @Test
    void testSm3HMAC() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        byte[] bytes = device.sm3Hmac(key, data);
        System.out.println(new String(bytes));
    }

//    //Hash
//    @Test
//    void testHash() throws Exception {
//
//        byte[] userId = "1234567812345678".getBytes();
//        //init
//        device.sm3HashInit();
//
//        //update
//        device.sm3HashUpdate(data);
//        device.sm3HashUpdate(data);
//
//        //final
//        byte[] bytes = device.sm3HashFinal();
//        System.out.println("sm3 hash 分步结果:" + new String(bytes));
//
//        byte[] bytes2 = device.sm3Hash(userId, data);
//        System.out.println("sm3 hash 一步结果:" + new String(bytes2));
//
//
//        //生成Sm2密钥对
//        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(1);
//        //公钥
//        SM2PublicKey pubKey = sm2KeyPair.getPubKey();
//
//        //init with pubKey
//        device.sm3HashInitWithPubKey(pubKey, userId);
//
//        //update
//        device.sm3HashUpdate(data);
//        device.sm3HashUpdate(data);
//
//        //final
//        byte[] bytes1 = device.sm3HashFinal();
//        System.out.println("sm3 hash 带公钥 分步结果:" + new String(bytes1));
//
//        byte[] bytes3 = device.sm3HashWithPubKey(pubKey, userId, data);
//        System.out.println("sm3 hash 带公钥 一步结果:" + new String(bytes3));
//
//
//    }


    //获取连接个数
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

    //验证证书（一） success
    @Test
    void testVerifyCert() throws Exception {
        int i = device.validateCertificate(cert);
        assert i == 0;
//        device.isCertificateRevoked(cert);
    }

    //验证证书（二） ignore
    @Test
    @Ignore
    void testVerifyCert2() throws Exception {
        byte[] crlData = new byte[0];
        boolean certificateRevoked = device.isCertificateRevoked(cert, crlData);
        assert !certificateRevoked;
    }

    //获取证书信息 success
    @Test
    void testGetCertInfo() throws Exception {
        byte[] cert = FileUtil.readBytes(userCertFileSM2);
        for (int i = 1; i < 36; i++) {
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
            byte[] certInfoByOid = device.getCertInfoByOid(cert, b);
            System.out.println(new String(certInfoByOid));
        }

    }

    //获取设备证书 success
    @Test
    void testGetDeviceCert() throws Exception {
        byte[] deviceCert = device.getServerCert();
        System.out.println(new String(deviceCert));
    }

    //获取应用实体信息 success
    @Test
    void testGetAppEntityInfo() throws Exception {
        AFSvCryptoInstance instance = device.getInstance("zzytest");
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
        String policyName = "zzytest";
        byte[] signCertByPolicyName = device.getSignCertByPolicyName(policyName);
        System.out.println(new String(signCertByPolicyName));
    }


    //获取证书的OCSP地址
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
        //签名证书
        byte[] cert = deviceCert;


        //签名信息编码
        byte[] bytes = device.encodeSignedDataForSM2(encoded, cert, data);
        System.out.println("第一次签名信息编码,不带原文"+new String(bytes));
        byte[] bytes1 = device.encodeSignedDataForSM2(true, encoded, cert, data);
        System.out.println("第二次签名信息编码,带原文"+new String(bytes1));



//        //签名信息解码
//        AFSM2DecodeSignedData afsm2DecodeSignedData = device.decodeSignedDataForSM2(bytes);
//        System.out.println("第一次签名信息解码,不带原文"+afsm2DecodeSignedData);
//        AFSM2DecodeSignedData afsm2DecodeSignedData1 = device.decodeSignedDataForSM2(bytes1);
//        System.out.println("第二次签名信息解码,带原文"+afsm2DecodeSignedData1);
//

        //签名信息验证
        boolean b = device.verifySignedDataForSM2(bytes, data);
        System.out.println("第一次签名信息验证,不带原文"+b);
        boolean b1 = device.verifySignedDataForSM2(bytes1, null);
        System.out.println("第二次签名信息验证,带原文"+b1);

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
        byte[] encCert = deviceEncCert;

        //数字信封编码
        byte[] bytes = device.encodeEnvelopedDataForSM2(encoded, key, cert, encCert, key);
        System.out.println("第一次数字信封编码"+new String(bytes));

        //数字信封解码
        AFPkcs7DecodeData afPkcs7DecodeData = device.decodeEnvelopedDataForSM2(encoded, bytes);
        System.out.println("第一次数字信封解码"+afPkcs7DecodeData);


    }

    @Test
    void test111() {
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(getPriKey());
        System.out.println(sm2PrivateKey);
    }

    //获取设备私钥
    private byte[] getPriKey() {
        String s = "AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAl3YS3pFS/9AER8kalJdsukEGKCvcojT3/gi8d3Kxh4sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ5DrFDxCNoyjTvBZyfs+79sSTgZbIVx/+cpEvD/MqQ0AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtxQvC680o3tk6HvtX+RM6+hUI7s9qu+nZlDRoewyvIU=";
        byte[] decode = Base64.decode(s);
        //删除前132字节
        byte[] bytes = Arrays.copyOfRange(decode, 132, decode.length);
        return bytes;
    }


    //endregion

}