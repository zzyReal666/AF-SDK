package com.af.device.impl;

import cn.hutool.core.util.HexUtil;
import com.af.bean.RequestMessage;
import com.af.constant.CMDCode;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.device.AFDeviceFactory;
import com.af.device.DeviceInfo;
import com.af.netty.AFNettyClient;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.signAndVerify.sm2.SM2PrivateKeyStructure;
import com.af.utils.BigIntegerUtil;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import com.af.utils.SM4Utils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
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
     *
     */
    @Test
    void testGetRandom2() throws Exception {
        byte[] random = device.getRandom(5);
        System.out.println(Arrays.toString(random));
    }

    //导出公钥信息
    @Test
    void testGetPublicKey() throws Exception {
//        //RSA 签名
        byte[] rsaPublicKey = device.getRSAPublicKey(1, 0);
        System.out.println( "RSA签名公钥:" + new String(rsaPublicKey));
        //RSA加密
        byte[] rsaPublicKey2 = device.getRSAPublicKey(1, 1);
        System.out.println( "RSA加密公钥:" + new String(rsaPublicKey2));
        //SM2 签名
        byte[] sm2PublicKey = device.getSm2PublicKey(1, 0);
        System.out.println( "SM2签名公钥:" + new String(sm2PublicKey));
        //SM2加密
        byte[] sm2PublicKey2 = device.getSm2PublicKey(1, 1);
        System.out.println( "SM2加密公钥:" + new String(sm2PublicKey2));
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

        RSAKeyPair rsaKeyPair = device.generateRSAKeyPair( ModulusLength.LENGTH_1024);
        System.out.println("RSA密钥对:" + rsaKeyPair);
    }

    //释放密钥信息
    @Test
    void testReleaseKeyPair() throws Exception {
        device.releaseKeyPair(2);
    }

    //RSA 操作
    @Test
    void testRSA() throws Exception {

        //RSA 内部签名验签
        byte[] bytes = device.rsaSignature(1, data);
        boolean b = device.rsaVerify(1, data, bytes);

        //RSA 外部签名验签
        RSAKeyPair rsaKeyPair = device.generateRSAKeyPair( ModulusLength.LENGTH_1024);
        byte[] bytes1 = device.rsaSignature(rsaKeyPair.getPriKey().encode(), data);
        boolean b1 = device.rsaVerify(rsaKeyPair.getPubKey().encode(), data, bytes1);

        //RSA内部密钥加解密
        byte[] bytes2 = device.rsaEncrypt(1, data);
        byte[] bytes3 = device.rsaDecrypt(1, bytes2);
        assert Arrays.equals(data, bytes3);

//        //RSA 外部密钥加解密
//        byte[] bytes4 = device.rsaEncrypt(rsaKeyPair.getPubKey().encode(), data);
//        byte[] bytes5 = device.rsaDecrypt(rsaKeyPair.getPriKey().encode(), bytes4);
//        assert Arrays.equals(data, bytes5);

    }
    //SM2 操作
    @Test
    void testSM2() throws Exception {
        //SM2 内部签名验签
        byte[] bytes = device.sm2Signature(1, data);
        boolean b = device.sm2Verify(1, data, bytes);
        assert b;

//        //SM2 外部签名验签
//        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(0, ModulusLength.LENGTH_256);
//        byte[] bytes1 = device.sm2Signature(sm2KeyPair.getPriKey().encode(), data);
//        boolean b1 = device.sm2VerifyByPublicKey(sm2KeyPair.getPubKey().encode(), data, bytes1);
//        assert b1;
//
        //SM2内部密钥加解密
        byte[] bytes2 = device.sm2Encrypt(1, data);
        byte[] bytes3 = device.sm2Decrypt(1, bytes2);
        assert Arrays.equals(data, bytes3);

//        //SM2 外部密钥加解密
//        SM2KeyPair sm2KeyPair1 = device.generateSM2KeyPair(1, ModulusLength.LENGTH_256);
//        byte[] bytes4 = device.sm2Encrypt(sm2KeyPair1.getPubKey().encode(), data);
//        byte[] bytes5 = device.sm2Decrypt(sm2KeyPair1.getPriKey().encode(), bytes4);
//        assert Arrays.equals(data, bytes5);


    }

    //对称操作 批量对称
    @Test
    void testSymmetric() throws Exception {

    }

    //验证证书有效性
    @Test
    void testVerifyCertificate() throws Exception {
        //证书
        String userCertValue = BytesOperate.readFileByLine(userCertFileRSA);
        //验证证书有效性
        int i = device.validateCertificate(userCertValue.getBytes());
        assert i == 0;

    }

    //MAC
    @Test
    void testMAC() throws Exception {

    }
    //SM3_HMAC
    @Test
    void testSM3_HMAC() throws Exception {

    }
    //HASH
    @Test
    void testHASH() throws Exception {

        //init update final

    }


    //获取内部对称密钥句柄
    @Test
    void testGetSymmetricKeyHandle() throws Exception {

    }
    //获取连接个数
    @Test
    void testGetConnectionCount() throws Exception {

    }


















    //验证证书是否被吊销 todo crl文件
    @Test
    void testVerifyCertificate2() throws Exception {
        //证书
        String userCertValue = BytesOperate.readFileByLine(userCertFileRSA);
        //crl
        String crlValue = BytesOperate.readFileByLine("src\\test\\resources\\crl.crl");
        //验证证书有效性
        boolean certificateRevoked = device.isCertificateRevoked(userCertValue.getBytes(), crlValue.getBytes());
        assert !certificateRevoked;

    }


    //========================================================RSA========================================================

    /**
     * 导出RSA公钥
     */
    @Test
    void testGetRSAPublicKey() throws Exception {
        byte[] rsaPublicKey = device.getRSAPublicKey(1, 0);
        System.out.println(Arrays.toString(rsaPublicKey));
    }

    /**
     * RSA 内部密钥签名验签
     */
    @Test
    void testRSASign_Verify() throws Exception {
        byte[] signature = device.rsaSignature(2, data);
        boolean b = device.rsaVerify(2, data, signature);
        assert b;
    }

    /**
     * RSA 外部密钥签名验签  todo 私钥构建
     */
    @Test
    void testRSASign_Verify2() throws Exception {
        //签名
        byte[] bytes = device.rsaSignature(data, getSM2PrivateKey(sm2PrvKeyDataBase64));
        //证书
        String userCertValue = BytesOperate.readFileByLine(userCertFileRSA);
        //验签
        boolean b = device.rsaVerifyByCertificate(userCertValue.getBytes(StandardCharsets.UTF_8), data, bytes);
        assert b;
    }

    /**
     * RSA 内部密钥 文件签名验签
     */
    @Test
    void testRSASign_Verify3() throws Exception {
        byte[] bytes = device.rsaSignFile(1, fileName);
        boolean b = device.rsaVerifyFile(1, fileName, bytes);
        assert b;
    }


    /**
     * RSA 外部密钥 文件签名验签   todo 私钥构建
     */
    @Test
    void testRSASign_Verify4() throws Exception {
        //签名
        byte[] bytes = device.rsaSignFile(fileName, getSM2PrivateKey(sm2PrvKeyDataBase64));
        //证书
        String userCertValue = BytesOperate.readFileByLine(userCertFileRSA);
        //验签
        boolean b = device.rsaVerifyFileByCertificate(userCertValue.getBytes(StandardCharsets.UTF_8), fileName, bytes);
        assert b;
    }


    /**
     * RSA 内部密钥 加密解密
     */
    @Test
    void testRSAEncrypt_Decrypt() throws Exception {
        byte[] bytes = device.rsaEncrypt(1, data);
        byte[] bytes1 = device.rsaDecrypt(1, bytes);
        assert Arrays.equals(data, bytes1);
    }

    /**
     * RSA 外部密钥 加密解密  todo 私钥构建
     */
    @Test
    void testRSAEncrypt_Decrypt2() throws Exception {
        //加密
        byte[] bytes = device.rsaEncrypt(data, getSM2PrivateKey(sm2PrvKeyDataBase64));
        //解密
        byte[] bytes1 = device.rsaDecrypt(bytes, getSM2PrivateKey(sm2PrvKeyDataBase64));
        assert Arrays.equals(data, bytes1);
    }


    //=====================================================SM2=====================================================


    /**
     * 获取SM2私钥
     *
     * @param privateKey 私钥
     * @return ASN1 DER编码的私钥
     */
    public static byte[] getSM2PrivateKey(String privateKey) throws Exception {
        byte[] prvKey = BytesOperate.base64DecodeData(privateKey);
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(prvKey);
        BigInteger d = BigIntegerUtil.toPositiveInteger(sm2PrivateKey.getD());
        SM2PrivateKeyStructure structure = new SM2PrivateKeyStructure(d);
        return BytesOperate.base64EncodeData(structure.toASN1Primitive().getEncoded("DER"));
    }


    /**
     * 内部密钥签名验签
     */
    @Test
    void testSign_Verify() throws Exception {
        byte[] signature = device.sm2Signature(2, data);
        boolean b = device.sm2Verify(2, data, signature);
        assert b;
    }

    /**
     * 外部密钥签名验签
     */
    @Test
    void testSign_Verify2() throws Exception {
        //签名
        byte[] bytes = device.sm2Signature(data, getSM2PrivateKey(sm2PrvKeyDataBase64));
        //证书
        String userCertValue = BytesOperate.readFileByLine(userCertFileSM2);
        //验签
        boolean b = device.sm2VerifyByCertificate(userCertValue.getBytes(StandardCharsets.UTF_8), data, bytes);
        assert b;
    }


    /**
     * 基于证书的SM2签名验签
     */
    @Test
    void testSign_Verify3() throws Exception {
        //签名  todo 私钥和证书
        byte[] bytes = device.sm2SignatureByCertificate(data, null, null);
        //证书
        String userCertValue = BytesOperate.readFileByLine(userCertFileSM2);
        //验签
        boolean b = device.sm2VerifyByCertificate(userCertValue.getBytes(StandardCharsets.UTF_8), data, bytes);
        assert b;
    }

    //SM2文件签名验签 内部密钥
    @Test
    void testSign_Verify4() throws Exception {
        byte[] bytes = device.sm2SignFile(1, fileName);
        boolean b = device.sm2VerifyFile(1, fileName, bytes);
        assert b;
    }

    //SM2文件签名验签 外部密钥
    @Test
    void testSign_Verify5() throws Exception {
        byte[] bytes = device.sm2SignFile(fileName, getSM2PrivateKey(sm2PrvKeyDataBase64));
        String userCertValue = BytesOperate.readFileByLine(userCertFileSM2);
        boolean b = device.sm2VerifyFileByCertificate(userCertValue.getBytes(StandardCharsets.UTF_8), fileName, bytes);
        assert b;
    }

    //SM2文件签名验签 证书
    @Test
    void testSign_Verify6() throws Exception {
        byte[] bytes = device.sm2SignFile(fileName, getSM2PrivateKey(sm2PrvKeyDataBase64));
        String userCertValue = BytesOperate.readFileByLine(userCertFileSM2);
        boolean b = device.sm2VerifyFileByCertificate(userCertValue.getBytes(StandardCharsets.UTF_8), fileName, bytes);
        assert b;
    }


    //SM2文件加密解密 内部密钥

    @Test
    void testEncrypt_Decrypt() throws Exception {
        byte[] bytes = device.sm2Encrypt(1, data);
        byte[] bytes1 = device.sm2Decrypt(1, bytes);
        assert Arrays.equals(data, bytes1);
    }


    //SM2文件加密解密 外部密钥
    @Test
    void testEncrypt_Decrypt2() throws Exception {
        byte[] bytes = device.sm2Encrypt(data, getSM2PrivateKey(sm2PrvKeyDataBase64));
        byte[] bytes1 = device.sm2Decrypt(bytes, getSM2PrivateKey(sm2PrvKeyDataBase64));
        assert Arrays.equals(data, bytes1);
    }

    //SM2文件加密解密 证书
    @Test
    void testEncrypt_Decrypt3() throws Exception {
        byte[] bytes = device.sm2EncryptByCertificate(data, getSM2PrivateKey(sm2PrvKeyDataBase64));
        byte[] bytes1 = device.sm2Decrypt(bytes, getSM2PrivateKey(sm2PrvKeyDataBase64));
        assert Arrays.equals(data, bytes1);
    }


    //查询证书信任列表

    //获取证书的个数

    // 根据别名获取单个证书

    // 删除用户证书列表


    // 获取服务器证书


    // 根据策略名称，获取相应的证书


    // 获取证书中的OCSP URL地址


    // 获取证书信息


    // 获取证书扩展信息


}