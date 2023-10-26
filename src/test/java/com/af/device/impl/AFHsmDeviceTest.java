package com.af.device.impl;

import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.RandomUtil;
import com.af.constant.Algorithm;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.crypto.key.symmetricKey.SessionKey;
import com.af.exception.AFCryptoException;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.impl.agreementData.AgreementData;
import com.af.struct.signAndVerify.CsrRequest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

class AFHsmDeviceTest {

    static Logger logger = Logger.getLogger("AFHsmDeviceTest");
    static AFHsmDevice device;
    static byte[] data = "hello/密码服务接口测试".getBytes(StandardCharsets.UTF_8);

//    static byte[] data = FileUtil.readBytes("bigData");

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        device = new AFHsmDevice.Builder("192.168.90.40", 8008, "abcd1234")
                .responseTimeOut(100000)
                .connectTimeOut(10000)
                .channelCount(16)
                .managementPort(443)
                .build();


//        //获取私钥访问权限
//        device.getPrivateKeyAccessRight(1, 3, "12345678");
//        //获取私钥访问权限
//        device.getPrivateKeyAccessRight(1, 4, "12345678");
    }


    @AfterAll
    static void tearDown() throws Exception {
        logger.info("发送关闭连接请求");
        device.close(AFHsmDevice.getClient());
        logger.info("服务端已经关闭连接");
    }


    //region//======>p10 证书申请<======

    //根据id删除密钥
    @Test
    void testDeleteKeyPair() throws Exception {
        device.deleteKey(5);
    }

    //生成p10
    @Test
    void testGetCSRByIndex() throws Exception {
        CsrRequest csrRequest = new CsrRequest("cn", "sd", "jn", "szaf", "szaf", "zzyzzy", "zzypersonally@gmail.com");
        String csrByIndex = device.getCSRByIndex(5, csrRequest);
        System.out.println("CSR:" + csrByIndex);
    }

    //根据密钥索引导入证书
    @Test
    void testImportCertByIndex() throws AFCryptoException {

        String sigCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICaTCCAg+gAwIBAgIJAOWoGwJCnb9cMAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT\n" +
                "AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK\n" +
                "DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X\n" +
                "DTIzMDgyNDAyNDE0MFoXDTI0MDgyMzAyNDE0MFowfjELMAkGA1UEBgwCY24xCzAJ\n" +
                "BgNVBAgMAnNkMQswCQYDVQQHDAJqbjENMAsGA1UECgwEc3phZjENMAsGA1UECwwE\n" +
                "c3phZjEPMA0GA1UEAwwGenp5enp5MSYwJAYJKoZIhvcNAQkBFhd6enlwZXJzb25h\n" +
                "bGx5QGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABKqDPjxb0JJf\n" +
                "FunuJIhee6c54okChn3QGZZo/KIummTYKN1zyI1/M55ZJx+ozglSzQYtY2yWjk6S\n" +
                "533DeQP2/QqjgYwwgYkwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCB4AwLAYJYIZI\n" +
                "AYb4QgENBB8WHUdNQ2VydC5vcmcgU2lnbmVkIENlcnRpZmljYXRlMB0GA1UdDgQW\n" +
                "BBRfrqABQGAPIus56IkhI++jJv1aFzAfBgNVHSMEGDAWgBR/Wl47AIRZKg+YvqEO\n" +
                "bzmVQxBNBzAKBggqgRzPVQGDdQNIADBFAiATXWwtV6mFSikAeJNkrr+S9h/bwSC+\n" +
                "f5q57FgOAnobZwIhAMJbXP2lYupYUVXXRxX1GNkh7b89TRjSjBouklKvAl/N\n" +
                "-----END CERTIFICATE-----\n";
        String encCert = "";
        String encPriKey = "";
        device.importCertByIndex(5, sigCert, encCert, encPriKey);
    }

    //根据密钥索引获取证书
    @Test
    void testGetCertByIndex() throws AFCryptoException {
        Map<String, String> certByIndex = device.getCertByIndex(5);
        System.out.println("证书:" + certByIndex);
    }
    //endregion


    //region//======> 对称加密 通用接口 <======

    //AES
    @Test
    void testAESECB() throws AFCryptoException {

        //SM1 SM4 16 | DES 8 | AES 16  |3DES 24  | AES192 24
        int keyLen = 16;
        byte[] key = RandomUtil.randomBytes(keyLen);
        byte[] iv = RandomUtil.randomBytes(keyLen);

        //ECB
        byte[] bytes = device.symmEncrypt(Algorithm.SGD_AES_ECB, key, null, data);
        byte[] bytes1 = device.symmDecrypt(Algorithm.SGD_AES_ECB, key, null, bytes);
        assert Arrays.equals(data, bytes1);
        System.out.println("AES ECB SUCCESS");

        //CBC
        byte[] bytes2 = device.symmEncrypt(Algorithm.SGD_AES_CBC, key, iv, data);
        byte[] bytes3 = device.symmDecrypt(Algorithm.SGD_AES_CBC, key, iv, bytes2);
        assert Arrays.equals(data, bytes3);
        System.out.println("AES CBC SUCCESS");

//        //OFB
//        byte[] bytes4 = device.symmEncrypt(Algorithm.SGD_AES_OFB, key, iv, data);
//        byte[] bytes5 = device.symmDecrypt(Algorithm.SGD_AES_OFB, key, iv, bytes4);
//        assert Arrays.equals(data, bytes5);
//        System.out.println("AES OFB SUCCESS");
//
//        //CFB
//        byte[] bytes6 = device.symmEncrypt(Algorithm.SGD_AES_CFB, key, iv, data);
//        byte[] bytes7 = device.symmDecrypt(Algorithm.SGD_AES_CFB, key, iv, bytes6);
//        assert Arrays.equals(data, bytes7);
//        System.out.println("AES CFB SUCCESS");
//
//        //CTR
//        byte[] bytes8 = device.symmEncrypt(Algorithm.SGD_AES_CTR, key, iv, data);
//        byte[] bytes9 = device.symmDecrypt(Algorithm.SGD_AES_CTR, key, iv, bytes8);
//        assert Arrays.equals(data, bytes9);
//        System.out.println("AES CTR SUCCESS");
    }

    //SM1
    @Test
    void testSM1() throws Exception {
        //SM1 SM4 16 | DES 8 | AES 16  |3DES 24  | AES192 24
        int keyLen = 16;
        byte[] key = RandomUtil.randomBytes(keyLen);
        byte[] iv = RandomUtil.randomBytes(keyLen);

        //ECB
        byte[] bytes = device.symmEncrypt(Algorithm.SGD_SM1_ECB, key, null, data);
        byte[] bytes1 = device.symmDecrypt(Algorithm.SGD_SM1_ECB, key, null, bytes);
        assert Arrays.equals(data, bytes1);
        System.out.println("SM1 ECB SUCCESS");

        //CBC
        byte[] bytes2 = device.symmEncrypt(Algorithm.SGD_SM1_CBC, key, iv, data);
        byte[] bytes3 = device.symmDecrypt(Algorithm.SGD_SM1_CBC, key, iv, bytes2);
        assert Arrays.equals(data, bytes3);
        System.out.println("SM1 CBC SUCCESS");
    }


    //DES
    @Test
    void testDESECB() throws AFCryptoException {
        //SM1 SM4 16 | DES 8 | AES 16  |3DES 24  | AES192 24
        int keyLen = 8;
        byte[] key = RandomUtil.randomBytes(keyLen);
        byte[] iv = RandomUtil.randomBytes(keyLen);

        //ECB
        byte[] bytes = device.symmEncrypt(Algorithm.SGD_DES_ECB, key, null, data);
        byte[] bytes1 = device.symmDecrypt(Algorithm.SGD_DES_ECB, key, null, bytes);
        assert Arrays.equals(data, bytes1);
        System.out.println("DES ECB SUCCESS");

        //CBC
        byte[] bytes2 = device.symmEncrypt(Algorithm.SGD_DES_CBC, key, iv, data);
        byte[] bytes3 = device.symmDecrypt(Algorithm.SGD_DES_CBC, key, iv, bytes2);
        assert Arrays.equals(data, bytes3);
        System.out.println("DES CBC SUCCESS");

//        //OFB
//        byte[] bytes4 = device.symmEncrypt(Algorithm.SGD_DES_OFB, key, iv, data);
//        byte[] bytes5 = device.symmDecrypt(Algorithm.SGD_DES_OFB, key, iv, bytes4);
//        assert Arrays.equals(data, bytes5);
//        System.out.println("DES OFB SUCCESS");

//        //CFB
//        byte[] bytes6 = device.symmEncrypt(Algorithm.SGD_DES_CFB, key, iv, data);
//        byte[] bytes7 = device.symmDecrypt(Algorithm.SGD_DES_CFB, key, iv, bytes6);
//        assert Arrays.equals(data, bytes7);
//        System.out.println("DES CFB SUCCESS");

//        //CTR
//        byte[] bytes8 = device.symmEncrypt(Algorithm.SGD_DES_CTR, key, iv, data);
//        byte[] bytes9 = device.symmDecrypt(Algorithm.SGD_DES_CTR, key, iv, bytes8);
//        assert Arrays.equals(data, bytes9);
//        System.out.println("DES CTR SUCCESS");

    }

    //3DES
    @Test
    void test3DESECB() throws AFCryptoException {
        //SM1 SM4 16 | DES 8 | AES 16  |3DES 24  | AES192 24
        int keyLen = 24;
        byte[] key = RandomUtil.randomBytes(keyLen);
        byte[] iv = RandomUtil.randomBytes(keyLen);

        //ECB
        byte[] bytes = device.symmEncrypt(Algorithm.SGD_3DES_ECB, key, null, data);
        byte[] bytes1 = device.symmDecrypt(Algorithm.SGD_3DES_ECB, key, null, bytes);
        assert Arrays.equals(data, bytes1);
        System.out.println("3DES ECB SUCCESS");

        //CBC
        byte[] bytes2 = device.symmEncrypt(Algorithm.SGD_3DES_CBC, key, iv, data);
        byte[] bytes3 = device.symmDecrypt(Algorithm.SGD_3DES_CBC, key, iv, bytes2);
        assert Arrays.equals(data, bytes3);

        System.out.println("3DES CBC SUCCESS");
    }

    //3DES 2KEY
    @Test
    void test3DES2KEYECB() throws AFCryptoException {
        //SM1 SM4 16 | DES 8 | AES 16  |3DES 24  | AES192 24
        int keyLen = 16;
        byte[] key = RandomUtil.randomBytes(keyLen);
        byte[] iv = RandomUtil.randomBytes(keyLen);
        byte[] iv_8 = RandomUtil.randomBytes(8);
//
//        //ECB
//        byte[] bytes = device.symmEncrypt(Algorithm.SGD_2DES_ECB, key, null, data);
//        byte[] bytes1 = device.symmDecrypt(Algorithm.SGD_2DES_ECB, key, null, bytes);
//        assert Arrays.equals(data, bytes1);
//        System.out.println("3DES 2KEY ECB SUCCESS");
//
//        //CBC
//        byte[] bytes2 = device.symmEncrypt(Algorithm.SGD_2DES_CBC, key, iv, data);
//        byte[] bytes3 = device.symmDecrypt(Algorithm.SGD_2DES_CBC, key, iv, bytes2);
//        assert Arrays.equals(data, bytes3);
//        System.out.println("3DES 2KEY CBC SUCCESS");

        //MAC
        byte[] bytes4 = device.mac(Algorithm.SGD_2DES_CBC, key, iv_8, data);
        System.out.println("3DES 2KEY MAC VALUE:" + HexUtil.encodeHexStr(bytes4));

    }


    //对称批量加解密
    @Test
    void testSymmBacth() throws Exception {

        //SM1 SM4 16 | DES 8 | AES 16  |3DES 24  | AES192 24
        int keyLen = 16;
        byte[] key = RandomUtil.randomBytes(keyLen);
        byte[] iv;


        List<Algorithm> algorithmList = new ArrayList<>();

        algorithmList.add(Algorithm.SGD_AES_ECB);
        algorithmList.add(Algorithm.SGD_AES_CBC);
        algorithmList.add(Algorithm.SGD_AES_OFB);
        algorithmList.add(Algorithm.SGD_AES_CFB);
        algorithmList.add(Algorithm.SGD_AES_CTR);
//
//        algorithmList.add(Algorithm.SGD_DES_ECB);
//        algorithmList.add(Algorithm.SGD_DES_CBC);
//        algorithmList.add(Algorithm.SGD_DES_OFB);
//        algorithmList.add(Algorithm.SGD_DES_CFB);
//        algorithmList.add(Algorithm.SGD_DES_CTR);
//
//        algorithmList.add(Algorithm.SGD_3DES_ECB);
//        algorithmList.add(Algorithm.SGD_3DES_CBC);
//        algorithmList.add(Algorithm.SGD_3DES_OFB);
//        algorithmList.add(Algorithm.SGD_3DES_CFB);
//        algorithmList.add(Algorithm.SGD_3DES_CTR);
//
//        algorithmList.add(Algorithm.SGD_SM1_ECB);
//        algorithmList.add(Algorithm.SGD_SM1_CBC);
//        algorithmList.add(Algorithm.SGD_SM1_OFB);
//        algorithmList.add(Algorithm.SGD_SM1_CFB);
//        algorithmList.add(Algorithm.SGD_SM1_CTR);
//
//        algorithmList.add(Algorithm.SGD_SM4_ECB);
//        algorithmList.add(Algorithm.SGD_SM4_CBC);
//        algorithmList.add(Algorithm.SGD_SM4_OFB);
//        algorithmList.add(Algorithm.SGD_SM4_CFB);
//        algorithmList.add(Algorithm.SGD_SM4_CTR);


        for (Algorithm algorithm : algorithmList) {
            try {
                if (algorithm.getName().contains("ECB")) {
                    iv = null;
                } else {
                    iv = RandomUtil.randomBytes(keyLen);
                }
                List<byte[]> list = new ArrayList<>();
                for (int i = 0; i < 100; i++) {
                    //i转数组添加到list
                    list.add(String.valueOf(i).getBytes());

                }
                List<byte[]> bytes = device.batchSymmEncrypt(algorithm, key, iv, list);
                List<byte[]> bytes1 = device.batchSymmDecrypt(algorithm, key, iv, bytes);
                //循环对比
                for (int i = 0; i < bytes1.size(); i++) {

                    assert Arrays.equals(list.get(i), bytes1.get(i));
                }
                System.out.println(algorithm.getName() + " SUCCESS");
            } catch (AFCryptoException e) {
                System.out.println(algorithm.getName() + " FAIL");
            }
        }
    }


    //endregion

    @Test
    void testReConnect() throws Exception {
        int i = 0;
        byte[] random = device.getRandom(5);
        System.out.println("第" + i++ + "次获取随机数:" + HexUtil.encodeHexStr(random));
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
        //
        SessionKey key1 = device.importSessionKey(Algorithm.SGD_SM2_2, 1, key.getKey());
        System.out.println("导入会话密钥SGD_SM2_2:" + key1);
        //释放密钥信息
        device.releaseSessionKey(key.getId());


        SessionKey key2 = device.generateSessionKey(Algorithm.SGD_RSA_ENC, 1, 16);
        System.out.println("会话密钥 SGD_RSA_ENC:" + key2);
        //导入会话密钥密文
        SessionKey key3 = device.importSessionKey(Algorithm.SGD_RSA_ENC, 1, key2.getKey());
        System.out.println("导入会话密钥 SGD_RSA_ENC:" + key3);
        //释放密钥信息
        device.releaseSessionKey(key2.getId());


        //生成 SM4加密的会话密钥
        SessionKey key4 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        System.out.println("会话密钥SGD_SMS4_ECB:" + key4);
        //导入会话密钥密文
        SessionKey key5 = device.importSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, key4.getKey());
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

    //生成协商数据 生成协商数据及密钥 生成协商密钥 success
    @Test
    void testGenerateAgreementData() throws Exception {
        AgreementData agreementData = new AgreementData();
        agreementData.setInitiatorId("szaf_zzyreq".getBytes());
        agreementData.setResponderId("szaf_zzyres".getBytes());

        //生成Sm2密钥对
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(0);
        //公钥
        agreementData.setPublicKey(sm2KeyPair.getPubKey().encode());
        agreementData.setTempPublicKey(sm2KeyPair.getPubKey().encode());
        agreementData.setResponderId("szaf_zzyres".getBytes());

        //生成协商数据
        AgreementData agreementData1 = device.generateAgreementData(1, ModulusLength.LENGTH_256, agreementData);
        System.out.println("协商数据:" + agreementData1);

        //生成协商数据及密钥

        AgreementData agreementData2 = device.generateAgreementDataAndKey(1, ModulusLength.LENGTH_256, agreementData);
        System.out.println("协商数据及密钥:" + agreementData2);
        //生成协商密钥
        AgreementData agreementData3 = device.generateAgreementKey(agreementData);
        System.out.println("协商密钥:" + agreementData3);

    }


    /**
     * 数字信封转换
     *
     * @deprecated 数据本身由内部密钥加密 传入的公钥是外部公钥 计算过程为:内部私钥先解密,再使用我们传入的外部公钥加密,返回加密后的数据
     */
    @Test
    void testEnvelope() throws Exception {
        //生成SM2密钥对
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(1);
        System.out.println("SM2密钥对:" + sm2KeyPair);
        //使用内部密钥加密data
        byte[] encodeData = device.sm2InternalEncrypt(1, data);

        //数字信封转换
        byte[] envelope = device.convertEnvelope(Algorithm.SGD_SM2_3, 1, sm2KeyPair.getPubKey().encode(), encodeData);

        //使用自己的密钥解密
        byte[] bytes = device.sm2ExternalDecrypt(sm2KeyPair.getPriKey(), envelope);
        assert Arrays.equals(data, bytes);
    }

    //RSA操作 success
    @Test
    void testRSA() throws Exception {
        //生成RSA密钥对
        RSAKeyPair rsaKeyPair = device.generateRSAKeyPair(ModulusLength.LENGTH_1024);
        System.out.println("RSA1024密钥对:" + rsaKeyPair);

        //使用内部密钥加解密
        //获取私钥访问权限
        device.getPrivateKeyAccessRight(1, 4, "12345678");
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
//        //使用内部密钥加解密
//        byte[] encodeData = device.sm2InternalEncrypt(1, data);
//        byte[] decodeData = device.sm2InternalDecrypt(1, encodeData);
//        assert Arrays.equals(data, decodeData);

        //使用外部密钥加解密
        byte[] encodeData1 = device.sm2ExternalEncrypt(sm2KeyPair.getPubKey(), data);
        byte[] decodeData1 = device.sm2ExternalDecrypt(sm2KeyPair.getPriKey(), encodeData1);
        assert Arrays.equals(data, decodeData1);
//
//        //使用内部密钥签名验签
//        //获取私钥访问权限
//        device.getPrivateKeyAccessRight(1, 3, "12345678");
//        byte[] sign = device.sm2InternalSign(1, data);
//        byte[] bytes = Sm2Util.change0018to0019(sign);  //todo 转换成0019 Base64 编码 ASN.1 DER 格式
//        byte[] bytes1 = Sm2Util.change0019to0018(bytes); //todo 转换成0018 R+S格式
//        boolean verify = device.sm2InternalVerify(1, data, bytes1);
//        assert verify;
//
//        //使用外部密钥签名验签
//        byte[] sign1 = device.sm2ExternalSign(sm2KeyPair.getPriKey(), data);
//        boolean verify1 = device.sm2ExternalVerify(sm2KeyPair.getPubKey(), data, sign1);
//        assert verify1;
    }

    //SM4
    @Test
    void testSm4() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        //iv
        byte[] iv = device.getRandom(16);

        //SM4 ECB 内部
        byte[] encodeData = device.sm4InternalEncryptECB(1, " ".getBytes());
        byte[] decodeData = device.sm4InternalDecryptECB(1, encodeData);
        assert Arrays.equals(" ".getBytes(), decodeData);

        //SM4 ECB 外部
        byte[] encodeData1 = device.sm4ExternalEncryptECB(key, data);
        byte[] decodeData1 = device.sm4ExternalDecryptECB(key, encodeData1);
        assert Arrays.equals(data, decodeData1);


        //SM4 ECB 密钥句柄
        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        System.out.println("SM4 ECB 密钥句柄:" + key1);
        byte[] bytes = device.sm4HandleEncryptECB(key1.getId(), data);
        byte[] bytes1 = device.sm4HandleDecryptECB(key1.getId(), bytes);
        //释放
        device.releaseSessionKey(key1.getId());
        assert Arrays.equals(data, bytes1);

        //SM4 CBC 内部
        byte[] encodeData2 = device.sm4InternalEncryptCBC(1, iv, data);
        byte[] decodeData2 = device.sm4InternalDecryptCBC(1, iv, encodeData2);
        assert Arrays.equals(data, decodeData2);

        //SM4 CBC 外部
        byte[] encodeData3 = device.sm4ExternalEncryptCBC(key, iv, data);
        byte[] decodeData3 = device.sm4ExternalDecryptCBC(key, iv, encodeData3);
        assert Arrays.equals(data, decodeData3);

        //SM4 CBC 密钥句柄
        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        byte[] bytes2 = device.sm4HandleEncryptCBC(key2.getId(), iv, data);
        byte[] bytes3 = device.sm4HandleDecryptCBC(key2.getId(), iv, bytes2);
        //释放密钥句柄
        device.releaseSessionKey(key2.getId());
        assert Arrays.equals(data, bytes3);


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

        //SM1 ECB 密钥句柄
        SessionKey key3 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        byte[] bytes4 = device.sm1HandleEncryptECB(key3.getId(), data);
        byte[] bytes5 = device.sm1HandleDecryptECB(key3.getId(), bytes4);
        //释放密钥句柄
        device.releaseSessionKey(key3.getId());
        assert Arrays.equals(data, bytes5);


        //SM1 CBC 内部
        byte[] encodeData6 = device.sm1InternalEncryptCBC(1, iv, data);
        byte[] decodeData6 = device.sm1InternalDecryptCBC(1, iv, encodeData6);
        assert Arrays.equals(data, decodeData6);

        //SM1 CBC 外部
        byte[] encodeData7 = device.sm1ExternalEncryptCBC(key, iv, data);
        byte[] decodeData7 = device.sm1ExternalDecryptCBC(key, iv, encodeData7);
        assert Arrays.equals(data, decodeData7);

        //SM1 CBC 密钥句柄
        SessionKey key4 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        byte[] bytes6 = device.sm1HandleEncryptCBC(key4.getId(), iv, data);
        byte[] bytes7 = device.sm1HandleDecryptCBC(key4.getId(), iv, bytes6);
        //释放密钥句柄
        device.releaseSessionKey(key4.getId());
        assert Arrays.equals(data, bytes7);
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
        list.add(null);
        list.add(null);
        list.add(data);
        list.add(null);
        list.add(null);
        list.add(null);
        list.add(data);
        list.add(data);
        list.add(null);
        list.add(null);
        list.add(data);

        //打印list  第i个元素为: list.get(i)
        for (int i = 0; i < list.size(); i++) {
            System.out.println("第" + i + "个元素:" + Hex.toHexString(list.get(i) == null ? new byte[0] : list.get(i)));
        }


        //SM4 ECB 内部
        List<byte[]> encodeList = device.sm4InternalBatchEncryptECB(1, list);
        //打印list
        for (int i = 0; i < list.size(); i++) {
            System.out.println("加密后第" + i + "个元素:" + Hex.toHexString(encodeList.get(i) == null ? new byte[0] : encodeList.get(i)));
        }
        List<byte[]> decodeList = device.sm4InternalBatchDecryptECB(1, encodeList);
        //打印list
        for (int i = 0; i < list.size(); i++) {
            System.out.println("解密后第" + i + "个元素:" + Hex.toHexString(decodeList.get(i) == null ? new byte[0] : decodeList.get(i)));
        }
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList.get(i));
        }

        //SM4 ECB 外部
        List<byte[]> encodeList1 = device.sm4ExternalBatchEncryptECB(key, list);
        List<byte[]> decodeList1 = device.sm4ExternalBatchDecryptECB(key, encodeList1);
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList1.get(i));
        }

        //SM4 ECB 密钥句柄
        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        List<byte[]> encodeList2 = device.sm4HandleBatchEncryptECB(key1.getId(), list);
        List<byte[]> decodeList2 = device.sm4HandleBatchDecryptECB(key1.getId(), encodeList2);
        //释放密钥句柄
        device.releaseSessionKey(key1.getId());
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList2.get(i));
        }

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

        //SM4 CBC 密钥句柄
        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        List<byte[]> encodeList5 = device.sm4HandleBatchEncryptCBC(key2.getId(), iv, list);
        List<byte[]> decodeList5 = device.sm4HandleBatchDecryptCBC(key2.getId(), iv, encodeList5);
        //释放密钥句柄
        device.releaseSessionKey(key2.getId());
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList5.get(i));
        }


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

        //SM1 ECB 密钥句柄
        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        List<byte[]> encodeList2 = device.sm1HandleBatchEncryptECB(key1.getId(), list);
        List<byte[]> decodeList2 = device.sm1HandleBatchDecryptECB(key1.getId(), encodeList2);
        //释放密钥句柄
        device.releaseSessionKey(key1.getId());
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList2.get(i));
        }

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

        //SM1 CBC 密钥句柄
        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
        List<byte[]> encodeList5 = device.sm1HandleBatchEncryptCBC(key2.getId(), iv, list);
        List<byte[]> decodeList5 = device.sm1HandleBatchDecryptCBC(key2.getId(), iv, encodeList5);
        //释放密钥句柄
        device.releaseSessionKey(key2.getId());
        for (int i = 0; i < list.size(); i++) {
            assert Arrays.equals(list.get(i), decodeList5.get(i));
        }

    }

    //MAC计算   singleChannel
    @Test
    void testMac() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        //iv
        byte[] iv = device.getRandom(16);

        //SM4 内部
        byte[] mac = device.sm4InternalMac(1, iv, data);
        System.out.println("SM4 内部 mac: " + Hex.toHexString(mac));

        //SM4 外部
        byte[] mac1 = device.sm4ExternalMac(key, iv, data);
        System.out.println("SM4 外部 mac: " + Hex.toHexString(mac1));

//        //SM4 密钥句柄
//        SessionKey key1 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        byte[] mac2 = device.sm4HandleMac(key1.getId(), iv, data);
//        //释放密钥句柄
//        device.releaseSessionKey(key1.getId());

        //SM1 内部
        byte[] mac3 = device.sm1InternalMac(1, iv, data);
        System.out.println("SM1 内部 mac: " + Hex.toHexString(mac3));

        //SM1 外部
        byte[] mac4 = device.sm1ExternalMac(key, iv, data);
        System.out.println("SM1 外部 mac: " + Hex.toHexString(mac4));

//        //SM1 密钥句柄
//        SessionKey key2 = device.generateSessionKeyBySym(Algorithm.SGD_SM4_ECB, 1, 16);
//        byte[] mac5 = device.sm1HandleMac(key2.getId(), iv, data);
//        //释放密钥句柄
//        device.releaseSessionKey(key2.getId());

    }

    //MAC 计算 通用
    @Test
    void testMac2() throws Exception {

    }

    //SM3-HMAC
    @Test
    void testSm3HMAC() throws Exception {
        //key
        byte[] key = device.getRandom(16);
        byte[] bytes = device.sm3Hmac(key, data);
        System.out.println(new String(bytes));
    }

    //Hash
    @Test
    void testHash() throws Exception {
        //不带公钥

        byte[] userId = "1234567812345678".getBytes();
        //init
        device.sm3HashInit();

        //update
        device.sm3HashUpdate(data);
        device.sm3HashUpdate(data);

        //final
        byte[] bytes = device.sm3HashFinal();
        System.out.println("sm3 hash 分步结果:" + HexUtil.encodeHexStr(bytes));


        //将data-data 拼接
        byte[] data1 = new byte[data.length * 2];
        System.arraycopy(data, 0, data1, 0, data.length);
        System.arraycopy(data, 0, data1, data.length, data.length);

        byte[] bytes2 = device.sm3Hash(data1);
        System.out.println("sm3 hash 一步结果:" + HexUtil.encodeHexStr(bytes2));
        assert Arrays.equals(bytes, bytes2);


        //带公钥

        //生成Sm2密钥对
        SM2KeyPair sm2KeyPair = device.generateSM2KeyPair(1);
        //公钥
        SM2PublicKey pubKey = sm2KeyPair.getPubKey();

        //init with pubKey
        device.sm3HashInitWithPubKey(pubKey, userId);

        //update
        device.sm3HashUpdate(data);

        //final
        byte[] bytes1 = device.sm3HashFinal();
        System.out.println("sm3 hash 带公钥 分步结果:" + HexUtil.encodeHexStr(bytes1));

        byte[] bytes3 = device.sm3HashWithPubKey(pubKey, userId, data);
        System.out.println("sm3 hash 带公钥 一步结果:" + HexUtil.encodeHexStr(bytes3));
        assert Arrays.equals(bytes1, bytes3);


    }

    //操作文件
    @Test
    void testOperateFile() throws Exception {


        //创建文件
        device.createFile("zzyTest", data.length);
        //写文件
        device.writeFile("zzyTest", 0, data);
        //读文件
        byte[] bytes = device.readFile("zzyTest", 0, data.length);
        assert Arrays.equals(data, bytes);
        //删除文件
        device.deleteFile("zzyTest");
//        byte[] bytes2 = device.readFile("zzyTest", 0, data.length);
    }


    //获取内部对称密钥句柄
    @Test
    void testGetInternalSymKeyHandle() throws Exception {
        int symKeyHandle = device.getSymKeyHandle(1);
        System.out.println(Integer.toHexString(symKeyHandle));
    }


    //获取连接个数
    @Test
    void testGetConnectNum() throws Exception {
        int connectNum = device.getConnectCount();
        System.out.println(connectNum);
    }
}