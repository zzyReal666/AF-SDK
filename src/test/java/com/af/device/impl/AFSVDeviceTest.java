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
//    static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.10.40", 8008, "abcd1234");
    static byte[] data = "1234567890abcdef".getBytes();

    static String sm2PubKeyDataBase64 = "AAEAAIHQcN4xEd3myIvZRFdf+M2jtBbh3Ik8aON7J55A91AAApm2+TtovD7Pl5dSQ/5RFbQcZQk9pm3orfKkgRYp/kY=";
    static String sm2PrvKeyDataBase64 = "AAEAAEnKCb0n669m/apkWqAOfz6MsQZD68yIShAbmdQ5MMDK";


    /**
     * 密钥协商
     */
    @Test
    void testAgreeKey() throws Exception {
        AFSVDevice afsvDevice = device.setAgKey();
        System.out.println(afsvDevice);
    }

    @Test
    void testGetRandom() throws Exception {
        DeviceInfo deviceInfo = device.getDeviceInfo();
        System.out.println(deviceInfo);
        byte[] random = device.getRandom(5);
        System.out.println(Arrays.toString(random));
    }

    @Test
    void testGetRSAPublicKey() throws Exception {
        byte[] rsaPublicKey = device.getRSAPublicKey(1, 1);
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
        String userCertFile = "src\\test\\resources\\user.crt";
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
}