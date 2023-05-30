package com.af.device.impl;

import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.device.AFDeviceFactory;
import com.af.device.DeviceInfo;
import com.af.struct.signAndVerify.sm2.SM2PrivateKeyStructure;
import com.af.utils.BigIntegerUtil;
import com.af.utils.BytesOperate;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


class AFSVDeviceTest {

    static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.1.224", 8008, "abcd1234");
    //    static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.10.40", 8012, "abcd1234").setAgKey();
    static byte[] data = "1234567890abcdef".getBytes();

    //证书文件路径
    static String userCertFile = "src\\test\\resources\\user.crt";

    //签名文件路径
    static byte[] fileName = "src\\test\\resources\\singFile.txt".getBytes(StandardCharsets.UTF_8);


    static String sm2PubKeyDataBase64 = "AAEAAIHQcN4xEd3myIvZRFdf+M2jtBbh3Ik8aON7J55A91AAApm2+TtovD7Pl5dSQ/5RFbQcZQk9pm3orfKkgRYp/kY=";
    static String sm2PrvKeyDataBase64 = "AAEAAEnKCb0n669m/apkWqAOfz6MsQZD68yIShAbmdQ5MMDK";


    /**
     * 获取私钥访问权限
     */
    @Test
    void testGetPrivateKeyAccessRight() throws Exception {
        device.getPrivateAccess(1);
    }

    /**
     * 密钥协商
     */
    @Test
    void testAgreeKey() throws Exception {
        AFSVDevice afsvDevice = device.setAgKey();
        System.out.println(afsvDevice);
    }

    /**
     * 随机数
     */
    @Test
    void testGetRandom() throws Exception {
        DeviceInfo deviceInfo = device.getDeviceInfo();
        System.out.println(deviceInfo);
        byte[] random = device.getRandom(5);
        System.out.println(Arrays.toString(random));
    }

    /**
     * 获取RSA公钥
     */
    @Test
    void testGetRSAPublicKey() throws Exception {
        byte[] rsaPublicKey = device.getRSAPublicKey(2, 1);
        System.out.println(Arrays.toString(rsaPublicKey));
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
        String userCertValue = BytesOperate.readFileByLine(userCertFile);
        //验签
        boolean b = device.sm2VerifyByCertificate(userCertValue.getBytes(StandardCharsets.UTF_8), data, bytes);
        assert b;
    }

    public static byte[] getSM2PrivateKey(String privateKey) throws Exception {
        byte[] prvKey = BytesOperate.base64DecodeData(privateKey);
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(prvKey);
        BigInteger d = BigIntegerUtil.toPositiveInteger(sm2PrivateKey.getD());
        SM2PrivateKeyStructure structure = new SM2PrivateKeyStructure(d);
        return BytesOperate.base64EncodeData(structure.toASN1Primitive().getEncoded("DER"));
    }


    //SM2文件签名验签 内部密钥
    @Test
    void testSign_Verify3() throws Exception {
        byte[] bytes = device.sm2SignFile(1, fileName);
        boolean b = device.sm2VerifyFile(1, fileName, bytes);
        assert b;
    }

    //SM2文件签名验签 外部密钥

    //SM2文件签名验签 证书


    //SM2文件加密解密 内部密钥

    //SM2文件加密解密 外部密钥

    //SM2文件加密解密 证书


    //导出公钥

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