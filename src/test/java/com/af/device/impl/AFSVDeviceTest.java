package com.af.device.impl;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.HexUtil;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.device.DeviceInfo;
import com.af.struct.signAndVerify.AFPkcs7DecodeData;
import com.af.struct.signAndVerify.AFSvCryptoInstance;
import com.af.struct.signAndVerify.CertAltNameTrustList;
import com.af.struct.signAndVerify.CsrRequest;
import com.af.struct.signAndVerify.RSA.RSAKeyPairStructure;
import com.af.struct.signAndVerify.sm2.SM2KeyPairStructure;
import com.af.struct.signAndVerify.sm2.SM2PrivateKeyStructure;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import com.af.utils.base64.Base64;
import org.junit.Ignore;
import org.junit.jupiter.api.AfterAll;
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

    //    static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.10.40", 8008, "abcd1234");
    static AFSVDevice device = new AFSVDevice.Builder("192.168.10.40", 8008, "abcd1234")
            .isAgKey(true)
            .responseTimeOut(100000)
            .build();

    //    static byte[] data = "1234567890abcde".getBytes();
    //大数据
    static byte[] data = FileUtil.readBytes("D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\bigData");

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


    @AfterAll
    static void tearDown() throws Exception {
        logger.info("发送关闭连接请求");
        device.close(AFSVDevice.getClient());
        logger.info("已经关闭连接");
    }


    //region //与HSM共有

    /**
     * 关闭连接 success
     */
    @Test
    void testClose() throws Exception {
        device.close(AFSVDevice.getClient());
    }

    /**
     * 获取私钥访问权限 success
     */
    @Test
    void testGetPrivateKeyAccessRight() throws Exception {
        device.getPrivateAccess(1, 3, "12345678");
        device.getPrivateAccess(1, 4, "12345678910");
        device.getPrivateAccess(15, 3, "12345678");
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
        DeviceInfo deviceInfo = device.getDeviceInfo();
        System.out.println(deviceInfo);
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


//        //计算公钥
//        byte[] sm2PubKeyFromPriKey = device.getSM2PubKeyFromPriKey(sm2SignPrivateKey);
//        System.out.println("计算出的公钥:" + HexUtil.encodeHexStr(sm2PubKeyFromPriKey));


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
        device.getPrivateAccess(1, 4, "12345678910");
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
        byte[] dataPath = "D:\\test.zip".getBytes();

        //RSA 内部密钥文件签名验签 success
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
        byte[] bytes = device.sm2Signature(1, data);
        boolean b = device.sm2Verify(1, data, bytes);
        assert b;

        //SM2 外部签名验签 success
        byte[] bytes1 = device.sm2Signature(sm2SignPrivateKey, data);
        boolean b1 = device.sm2Verify(sm2SignPublicKey, data, bytes1);
        assert b1;

        //SM2 私钥签名 带z值
        byte[] bytes2 = device.sm2SignatureByPrivateKey(priKey, data);
        boolean b2 = device.sm2VerifyByCertificate(cert, data, bytes2);
        assert b2;

        //SM2 私钥签名 带证书
        byte[] bytes3 = device.sm2SignatureByCertificate(priKey, data, cert);
        boolean b3 = device.sm2VerifyByCertificate(cert, cert, data, bytes3);
        assert b3;

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
        byte[] cert = userCertFileSM2.getBytes();

        //读取文件
        byte[] dataPath = "D:\\test.zip".getBytes();

        //SM2 内部签名验签 success
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
        byte[] cert = userCertFileSM2.getBytes();


        //SM2 内部加解密 success
        byte[] bytes = device.sm2Encrypt(1, data);
        byte[] bytes1 = device.sm2Decrypt(1, bytes);
        assert Arrays.equals(data, BytesOperate.base64DecodeData(bytes1));

        //SM2 外部加解密
        byte[] bytes2 = device.sm2Encrypt(sm2SignPublicKey, data);
        byte[] bytes3 = device.sm2Decrypt(sm2SignPrivateKey, bytes2);
        assert Arrays.equals(data, BytesOperate.base64DecodeData(bytes3));


        //SM2 证书加密 外部私钥解密
        byte[] bytes4 = device.sm2EncryptByCertificate(cert, data);
        byte[] bytes5 = device.sm2Decrypt(priKey, bytes4);
        assert Arrays.equals(data, BytesOperate.base64DecodeData(bytes5));


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

    @Test
    void test006() throws Exception {
        System.out.println("文件大小：" + data.length / 1024 / 1024 + "MB");
        System.out.println("头：" + HexUtil.encodeHexStr(ArrayUtil.sub(data, 0, 10)));
        System.out.println("尾：" + HexUtil.encodeHexStr(ArrayUtil.sub(data, data.length - 10, data.length)));

        List<byte[]> list = new ArrayList<>();
        int itemSize = 2 * 1024 * 1024;
        BytesBuffer buf = new BytesBuffer(data);
        while (buf.size() > itemSize) {
            list.add(buf.read(itemSize));
        }
        list.add(buf.toBytes());

        System.out.println("分割份数：" + list.size());

        byte[] newData = new byte[0];
        for (int i = 0; i < list.size(); i++) {
            newData = ArrayUtil.addAll(newData, list.get(i));
        }
        System.out.println("文件大小：" + newData.length / 1024 / 1024 + "MB");
        System.out.println("头：" + HexUtil.encodeHexStr(ArrayUtil.sub(newData, 0, 10)));
        System.out.println("尾：" + HexUtil.encodeHexStr(ArrayUtil.sub(newData, newData.length - 10, newData.length)));

        byte[] newData111 = new byte[data.length];
        System.out.println("111文件大小：" + newData111.length / 1024 / 1024 + "MB");

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
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SMS4_ECB, 1, 16);
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

    //验证证书（一） success
    @Test
    void testVerifyCert() throws Exception {
        int i = device.validateCertificate(userCert);
        assert i == 0;
//        device.isCertificateRevoked(cert);
    }

    //验证证书（二） ignore
    @Test
    @Ignore
    void testVerifyCert2() throws Exception {
        byte[] crlData = new byte[0];
        boolean certificateRevoked = device.isCertificateRevoked(userCert, crlData);
        assert !certificateRevoked;
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
        //签名证书
        byte[] cert = deviceCert;


        //签名信息编码
        byte[] bytes = device.encodeSignedDataForSM2(encoded, cert, data);
        System.out.println("第一次签名信息编码,不带原文" + new String(bytes));
        byte[] bytes1 = device.encodeSignedDataForSM2(true, encoded, cert, data);
        System.out.println("第二次签名信息编码,带原文" + new String(bytes1));


//        //签名信息解码
//        AFSM2DecodeSignedData afsm2DecodeSignedData = device.decodeSignedDataForSM2(bytes);
//        System.out.println("第一次签名信息解码,不带原文"+afsm2DecodeSignedData);
//        AFSM2DecodeSignedData afsm2DecodeSignedData1 = device.decodeSignedDataForSM2(bytes1);
//        System.out.println("第二次签名信息解码,带原文"+afsm2DecodeSignedData1);
//

        //签名信息验证
        boolean b = device.verifySignedDataForSM2(bytes, data);
        System.out.println("第一次签名信息验证,不带原文" + b);
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
        byte[] encCert = null;

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

    //获取设备私钥
    private byte[] getPriKey() {
        byte[] bytes = FileUtil.readBytes(userCertPrivateKeyPath);
        byte[] decode = Base64.decode(bytes);
        //删除前132字节
        //Base64编码
        return Arrays.copyOfRange(decode, 132, decode.length);
    }

    @Test
    void testG() throws Exception {
        String s = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e049198cdad480c20d041bab7f73e8608aa055d2aa9925663f771b84f4bffcb98d86fec8679474dac27a8d1a6f738750270142762831df8d7c0b7d04d8fc3916ad504a370524c2322fb5a84442e7fd23613409e15ee6ff1ff4f97c328655e6fd9e226fb16caa7dda738204a3a42a51aa628aad61bc3563cf3e8421aff6e5d31f";
        String s2 = "";
        System.out.println(
                s.length()
        );
    }

    //endregion

    //region//======>http Request

    //根据密钥索引产生证书请求
    @Test
    void testGetCSRByIndex() throws Exception {
        String ip = "192.168.10.40";
        CsrRequest csrRequest = new CsrRequest();
        String csrByIndex = device.getCSRByIndex(9, csrRequest);
        System.out.println("CSR:" + csrByIndex);
    }

    //根据密钥索引导入证书
    @Test
    void testImportCertByIndex() throws Exception {
        String signCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICaDCCAg2gAwIBAgIJAOWoGwJCnbx6MAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
                "DTIzMDgwOTA3MTMxMloXDTI0MDgwODA3MTMxMlowfDELMAkGA1UEBgwCY24xCzAJ\n" +
                "BgNVBAgMAnNkMQswCQYDVQQHDAJqbjENMAsGA1UECgwEc3phZjENMAsGA1UECwwE\n" +
                "c3phZjENMAsGA1UEAwwEenp5MjEmMCQGCSqGSIb3DQEJARYXenp5cGVyc29uYWxs\n" +
                "eUBnbWFpbC5jb20wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATKJiGYDg3ANIn2\n" +
                "vf34oLrMdKpXLMBIY84b3R45r+0dC4ibwhAm2f44GZDBuBeUpZrRj5ZRE5nnqauU\n" +
                "0y4TCvMVo4GMMIGJMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgeAMCwGCWCGSAGG\n" +
                "+EIBDQQfFh1HTUNlcnQub3JnIFNpZ25lZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU\n" +
                "jXRDFg9Au/0mLIhRUgcaOIq9I14wHwYDVR0jBBgwFoAUf1peOwCEWSoPmL6hDm85\n" +
                "lUMQTQcwCgYIKoEcz1UBg3UDSQAwRgIhAJjsxxG6SSqWJ10ccJpwqzv2OHrsOiIu\n" +
                "xSPpsUk+RAo3AiEA+YD7w8HT768cmbqb6K+/6rqXE8r8rwnfVLMiCuwUszs=\n" +
                "-----END CERTIFICATE-----\n";
        String encCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICaDCCAg2gAwIBAgIJAOWoGwJCnbx7MAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
                "DTIzMDgwOTA3MTM0MVoXDTI0MDgwODA3MTM0MVowfDELMAkGA1UEBgwCY24xCzAJ\n" +
                "BgNVBAgMAnNkMQswCQYDVQQHDAJqbjENMAsGA1UECgwEc3phZjENMAsGA1UECwwE\n" +
                "c3phZjENMAsGA1UEAwwEenp5MjEmMCQGCSqGSIb3DQEJARYXenp5cGVyc29uYWxs\n" +
                "eUBnbWFpbC5jb20wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATKJiGYDg3ANIn2\n" +
                "vf34oLrMdKpXLMBIY84b3R45r+0dC4ibwhAm2f44GZDBuBeUpZrRj5ZRE5nnqauU\n" +
                "0y4TCvMVo4GMMIGJMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgM4MCwGCWCGSAGG\n" +
                "+EIBDQQfFh1HTUNlcnQub3JnIFNpZ25lZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU\n" +
                "jXRDFg9Au/0mLIhRUgcaOIq9I14wHwYDVR0jBBgwFoAUf1peOwCEWSoPmL6hDm85\n" +
                "lUMQTQcwCgYIKoEcz1UBg3UDSQAwRgIhAKfZdwRcM1gGkEgY2OnkAxeuQ9M+MVm7\n" +
                "mWak6T7YrNTLAiEA0V9zPtjiy46A7nucBWt59l8HN34Jm4bolI707Jofh5M=\n" +
                "-----END CERTIFICATE-----\n";

        device.importCertByIndex(6, "", encCert, "");
    }

    //根据密钥索引获取证书
    @Test
    void testGetCertByIndex() throws Exception {
        Map<String, String> certMap = device.getCertByIndex(72);
        System.out.println("cert:" + certMap);
    }

    //删除密钥
    @Test
    void testDeleteKey() throws Exception {
        String ip = "192.168.10.40";
        device.deleteKey(11);
    }
    //endregion

}