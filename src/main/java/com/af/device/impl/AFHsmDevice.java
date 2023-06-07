package com.af.device.impl;

import cn.hutool.core.util.HexUtil;
import com.af.constant.Algorithm;
import com.af.constant.ConstantNumber;
import com.af.constant.ModulusLength;
import com.af.crypto.algorithm.sm3.SM3;
import com.af.crypto.algorithm.sm3.SM3Impl;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.crypto.key.symmetricKey.SessionKey;
import com.af.device.DeviceInfo;
import com.af.device.IAFHsmDevice;
import com.af.device.cmd.AFHSMCmd;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.utils.BytesBuffer;
import com.af.utils.pkcs.AFPkcs1Operate;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description HSM设备实现类 用于实现HSM设备的各种算法 以及获取设备信息<br>
 * 该类为单例模式 通过getInstance方法获取实例<br>
 * 该层为对外接口层 用于对外提供各种算法的实现,实际message在具体算法实现类中构造<br>
 * 该层进行参数校验,具体调用在各个密码算法的实现中(获取设备信息和随机数在当前类中执行)<br>
 * @since 2023/4/27 14:53
 */
@Getter
public class AFHsmDevice implements IAFHsmDevice {
    private static final Logger logger = LoggerFactory.getLogger(AFHsmDevice.class);
    private byte[] agKey;  //协商密钥
    private static AFNettyClient client;  //netty客户端
    private final SM3 sm3 = new SM3Impl(client);  //国密SM3算法
    private final AFHSMCmd cmd = new AFHSMCmd(client, agKey);

    //==============================单例模式===================================
    private static final class InstanceHolder {
        static final AFHsmDevice instance = new AFHsmDevice();
    }

    public static AFHsmDevice getInstance(String host, int port, String passwd) {
        client = AFNettyClient.getInstance(host, port, passwd);
        return InstanceHolder.instance;
    }

    public AFHsmDevice setAgKey() {
        this.agKey = this.keyAgreement(client);
        cmd.setAgKey(agKey);
        logger.info("协商密钥成功,密钥为:{}", HexUtil.encodeHexStr(agKey));
        return this;
    }
    //==============================API===================================

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * 获取设备信息异常
     */

    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        return cmd.getDeviceInfo();

    }

    /**
     * 获取随机数
     * todo  增强
     *
     * @param length 随机数长度 字节数
     * @return 随机数
     * 获取随机数异常
     */
    public byte[] getRandom(int length) throws AFCryptoException {
        //参数检查
        if (length <= 0) {
            throw new AFCryptoException("随机数长度必须大于0");
        }

        return cmd.getRandom(length);
    }


    /**
     * 加解密分包  4096个字节一段 最后一段如果不足4096个字节 取实际长度
     *
     * @param data 数据
     * @return 分组后的数据 List<byte[]>
     */
    private List<byte[]> splitPackage(byte[] data) {
        int uiIndex;
        byte[] inputData;
        List<byte[]> bytes = new ArrayList<>();
        //分段加密 4096个字节一段 n-1段
        for (uiIndex = 0; uiIndex != (data.length / ConstantNumber.AF_LEN_4096); ++uiIndex) {
            inputData = new byte[ConstantNumber.AF_LEN_4096];
            System.arraycopy(data, ConstantNumber.AF_LEN_4096 * uiIndex, inputData, 0, ConstantNumber.AF_LEN_4096);
            bytes.add(inputData);
        }
        //最后一段 如果不足4096个字节 取实际长度
        if ((data.length % ConstantNumber.AF_LEN_4096) != 0) {
            inputData = new byte[data.length % ConstantNumber.AF_LEN_4096];
            System.arraycopy(data, ConstantNumber.AF_LEN_4096 * uiIndex, inputData, 0, inputData.length);
            bytes.add(inputData);
        }
        return bytes;
    }

//==============================导出公钥信息===================================

    /**
     * 获取SM2签名公钥
     *
     * @param index 索引
     * @return SM2签名公钥
     * 获取SM2签名公钥异常
     */
    public SM2PublicKey getSM2SignPublicKey(int index) throws AFCryptoException {
        byte[] bytes = cmd.exportPublicKey(index, Algorithm.SGD_SM2_1);
        return new SM2PublicKey(bytes);
    }

    /**
     * 获取SM2加密公钥
     *
     * @param index 索引
     * @return SM2加密公钥
     */
    public SM2PublicKey getSM2EncryptPublicKey(int index) throws AFCryptoException {
        byte[] bytes = cmd.exportPublicKey(index, Algorithm.SGD_SM2_2);
        return new SM2PublicKey(bytes);
    }

    /**
     * 获取RSA签名公钥信息
     *
     * @param index ：密钥索引
     * @return 返回RSA签名数据结构
     */

    public RSAPubKey getRSASignPublicKey(int index) throws AFCryptoException {
        byte[] bytes = cmd.exportPublicKey(index, Algorithm.SGD_RSA_SIGN);
        return new RSAPubKey(bytes);
    }

    /**
     * 获取RSA加密公钥信息
     *
     * @param index ： 密钥索引
     * @return 返回RSA加密数据结构
     */
    public RSAPubKey getRSAEncPublicKey(int index) throws AFCryptoException {
        byte[] rsaEncPublicKey = cmd.exportPublicKey(index, Algorithm.SGD_RSA_ENC);
        return new RSAPubKey(rsaEncPublicKey);
    }

    //=========================================生成密钥对=========================================

    /**
     * 生成密钥对 SM2
     *
     * @param keyType 密钥类型 0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对
     */
    public SM2KeyPair generateSM2KeyPair(int keyType) throws AFCryptoException {
        //签名密钥对
        if (keyType == ConstantNumber.SGD_SIGN_KEY_PAIR) {
            byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_SM2_1, ModulusLength.LENGTH_256);
            SM2KeyPair sm2KeyPair = new SM2KeyPair();
            sm2KeyPair.decode(bytes);
            return sm2KeyPair;
        }
        //密钥交换密钥对
        else if (keyType == ConstantNumber.SGD_ENC_KEY_PAIR) {
            byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_SM2_2, ModulusLength.LENGTH_256);
            SM2KeyPair sm2KeyPair = new SM2KeyPair();
            sm2KeyPair.decode(bytes);
            return sm2KeyPair;

        }
        //加密密钥对
        else if (keyType == ConstantNumber.SGD_EXCHANGE_KEY_PAIR) {
            byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_SM2_3, ModulusLength.LENGTH_256);
            SM2KeyPair sm2KeyPair = new SM2KeyPair();
            sm2KeyPair.decode(bytes);
            return sm2KeyPair;
        }
        //默认密钥对
        else if (keyType == ConstantNumber.SGD_KEY_PAIR) {
            byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_SM2, ModulusLength.LENGTH_256);
            SM2KeyPair sm2KeyPair = new SM2KeyPair();
            sm2KeyPair.decode(bytes);
            return sm2KeyPair;
        }
        //异常
        else {
            logger.error("密钥类型错误,keyType(0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对)={}", keyType);
            throw new AFCryptoException("密钥类型错误,keyType(0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对)=" + keyType);
        }
    }

    /**
     * 生成密钥对 RSA
     *
     * @param length 模长 {@link ModulusLength}
     */
    public RSAKeyPair generateRSAKeyPair(ModulusLength length) throws AFCryptoException {
        //length只能是1024或2048
        if (length != ModulusLength.LENGTH_1024 && length != ModulusLength.LENGTH_2048) {
            logger.error("RSA密钥模长错误,length(1024|2048)={}", length);
            throw new AFCryptoException("RSA密钥模长错误,length(1024|2048)=" + length);
        }
        byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_RSA, length);
        RSAKeyPair rsaKeyPair = new RSAKeyPair(bytes);
        rsaKeyPair.decode(bytes);
        return rsaKeyPair;
    }

    //=========================================会话密钥相关=========================================

    /**
     * 生成会话密钥 非对称加密
     *
     * @param algorithm ：对称算法标识  SGD_RSA_ENC|SGD_SM2_2
     * @param keyIndex  ：用于加密会话密钥的密钥索引
     * @param length    ：会话密钥长度 8|16|24|32
     * @return ：1、4 字节会话密钥 ID 2、4 字节加密信息长度 3、加密信息
     */
    public SessionKey generateSessionKey(Algorithm algorithm, int keyIndex, int length) throws AFCryptoException {
        //参数检查
        if (algorithm != Algorithm.SGD_RSA_ENC && algorithm != Algorithm.SGD_SM2_2) {
            logger.error("生成会话密钥失败,算法标识错误,algorithm(SGD_RSA_ENC|SGD_SM2_2):{}", algorithm);
            throw new AFCryptoException("生成会话密钥失败,算法标识错误,algorithm(SGD_RSA_ENC|SGD_SM2_2):" + algorithm);
        }
        byte[] bytes = cmd.generateSessionKey(algorithm, keyIndex, length);
        BytesBuffer buffer = new BytesBuffer(bytes);
        SessionKey key = new SessionKey();
        key.setId(buffer.readInt());
        key.setLength(buffer.readInt());
        key.setKey(buffer.read(key.getLength()));
        return key;

    }

    /**
     * 导入会话密钥密文 非对称加密
     *
     * @param algorithm ：对称算法标识  SGD_RSA_ENC|SGD_SM2_2
     * @param keyIndex  ：用于加密会话密钥的密钥索引
     * @param key       ：会话密钥密文
     * @return 会话密钥id 密钥长度
     */
    public SessionKey importSessionKey(Algorithm algorithm, int keyIndex, byte[] key) throws AFCryptoException {
        //参数检查
        if (algorithm != Algorithm.SGD_RSA_ENC && algorithm != Algorithm.SGD_SM2_2) {
            logger.error("导入会话密钥失败,算法标识错误,algorithm(SGD_RSA_ENC|SGD_SM2_2):{}", algorithm);
            throw new AFCryptoException("导入会话密钥失败,算法标识错误,algorithm(SGD_RSA_ENC|SGD_SM2_2):" + algorithm);
        }
        //获取私钥访问权限
        int keyType;
        if (algorithm == Algorithm.SGD_RSA_ENC) {
            keyType = 4;
        } else {
            keyType = 3;
        }
        getPrivateKeyAccessRight(keyIndex, keyType, "12345678");
        //导入会话密钥
        byte[] bytes = cmd.importSessionKey(algorithm, keyIndex, key);
        BytesBuffer buffer = new BytesBuffer(bytes);
        SessionKey sessionKey = new SessionKey();
        sessionKey.setId(buffer.readInt());
        return sessionKey;
    }

    /**
     * 数字信封转换
     *
     * @param algorithm 算法标识 SGD_RSA_ENC|SGD_SM2_3
     * @param keyIndex  密钥索引
     * @param pubKey    公钥
     * @param data      加密输入信息
     * @return 加密输出信息
     */
    public byte[] convertEnvelope(Algorithm algorithm, int keyIndex, byte[] pubKey, byte[] data) throws AFCryptoException {
        //参数检查
        if (algorithm != Algorithm.SGD_RSA_ENC && algorithm != Algorithm.SGD_SM2_3) {
            logger.error("数字信封转换失败,算法标识错误,algorithm(SGD_RSA_ENC|SGD_SM2_3):{}", algorithm);
            throw new AFCryptoException("数字信封转换失败,算法标识错误,algorithm(SGD_RSA_ENC|SGD_SM2_3):" + algorithm);
        }
        //获取私钥访问权限
        int keyType;
        if (algorithm == Algorithm.SGD_RSA_ENC) {
            keyType = 4;
        } else {
            keyType = 3;
        }
        getPrivateKeyAccessRight(keyIndex, keyType, "12345678");
        return cmd.convertEnvelope(algorithm, keyIndex, pubKey, data);

    }

    /**
     * 生成会话密钥（使用对称密钥）
     *
     * @param algorithm 加密算法标识 SGD_SM1_ECB|SGD_SMS4_ECB
     * @param keyIndex  加密密钥索引
     * @param length    会话密钥长度 8|16|24|32
     */
    public SessionKey generateSessionKeyBySym(Algorithm algorithm, int keyIndex, int length) throws AFCryptoException {
        //参数检查
        if (algorithm != Algorithm.SGD_SM1_ECB && algorithm != Algorithm.SGD_SMS4_ECB) {
            logger.error("生成会话密钥失败,算法标识错误,algorithm(SGD_SM1_ECB|SGD_SMS4_ECB):{}", algorithm);
            throw new AFCryptoException("生成会话密钥失败,算法标识错误,algorithm(SGD_SM1_ECB|SGD_SMS4_ECB):" + algorithm);
        }
        if (keyIndex < 0) {
            logger.error("生成会话密钥失败,加密密钥索引错误,keyIndex:{}", keyIndex);
            throw new AFCryptoException("生成会话密钥失败,加密密钥索引错误,keyIndex:" + keyIndex);
        }
        if (length != 8 && length != 16 && length != 24 && length != 32) {
            logger.error("生成会话密钥失败,会话密钥长度错误,length(8|16|24|32):{}", length);
            throw new AFCryptoException("生成会话密钥失败,会话密钥长度错误,length(8|16|24|32):" + length);
        }
        byte[] bytes = cmd.generateSessionKeyBySym(algorithm, keyIndex, length);
        BytesBuffer buffer = new BytesBuffer(bytes);
        SessionKey key = new SessionKey();
        key.setId(buffer.readInt());
        key.setLength(buffer.readInt());
        key.setKey(buffer.read(key.getLength()));
        return key;
    }

    /**
     * 导入会话密钥密文（使用对称密钥）
     *
     * @param algorithm 加密算法标识 SGD_SM1_ECB|SGD_SMS4_ECB
     * @param keyIndex  加密密钥索引
     * @param key       会话密钥密文
     */
    public SessionKey importSessionKeyBySym(Algorithm algorithm, int keyIndex, byte[] key) throws AFCryptoException {
        //参数检查
        if (algorithm != Algorithm.SGD_SM1_ECB && algorithm != Algorithm.SGD_SMS4_ECB) {
            logger.error("导入会话密钥失败,算法标识错误,algorithm(SGD_SM1_ECB|SGD_SMS4_ECB):{}", algorithm);
            throw new AFCryptoException("导入会话密钥失败,算法标识错误,algorithm(SGD_SM1_ECB|SGD_SMS4_ECB):" + algorithm);
        }
        byte[] bytes = cmd.importSessionKeyBySym(algorithm, keyIndex, key);
        BytesBuffer buffer = new BytesBuffer(bytes);
        SessionKey sessionKey = new SessionKey();
        sessionKey.setId(buffer.readInt());
        sessionKey.setLength(buffer.readInt());
        return sessionKey;
    }


    /**
     * 释放密钥信息
     *
     * @param id 4 字节密钥信息 ID
     */
    public void releaseSessionKey(int id) throws AFCryptoException {
        cmd.freeKey(id);
    }

    /**
     * 生成协商数据
     *
     * @param keyIndex 密钥索引
     * @param length   模长
     * @param id       发起方id
     */
    public byte[] generateAgreementData(int keyIndex, ModulusLength length, byte[] id) throws AFCryptoException {
        return cmd.generateAgreementData(keyIndex, length, id);
    }

    //todo  生成协商数据及密钥
    public byte[] generateAgreementDataAndKey(int keyIndex, ModulusLength length, byte[] id) throws AFCryptoException {
        return null;
    }

    /**
     * 生成协商密钥
     *
     * @param key    回复方公钥
     * @param temKey 回复方临时公钥
     * @param id     回复方id
     * @return 4 字节会话id HexString
     */
    public String generateAgreementKey(byte[] key, byte[] temKey, byte[] id) throws AFCryptoException {
        byte[] bytes = cmd.generateAgreementKey(key, temKey, id);
        BytesBuffer buffer = new BytesBuffer(bytes);
        return Integer.toHexString(buffer.readInt());
    }

//=========================================RSA计算=========================================

    /**
     * RSA内部加密运算
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 原始数据
     * @return ：返回运算结果
     */
    public byte[] rsaInternalEncrypt(int index, byte[] data) throws AFCryptoException {
        //填充
        byte[] bytes = AFPkcs1Operate.pkcs1EncryptionPublicKey(getRSAEncPublicKey(index).getBits(), data);
        //加密
        return cmd.rsaPublicKeyOperation(index, null, Algorithm.SGD_RSA_ENC, bytes);
    }


    /**
     * RSA内部解密运算 私钥解密
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 加密数据
     * @return ：返回运算结果
     */
    public byte[] rsaInternalDecrypt(int index, byte[] data) throws AFCryptoException {
        //获取私钥访问权限
        getPrivateKeyAccessRight(index, 4, "12345678");
        //解密
        byte[] bytes = cmd.rsaPrivateKeyOperation(index, null, Algorithm.SGD_RSA_ENC, data);
        //去填充
        return AFPkcs1Operate.pkcs1DecryptPublicKey(getRSAEncPublicKey(index).getBits(), bytes);
    }

    /**
     * RSA外部加密运算 公钥加密
     *
     * @param publicKey ：RSA公钥信息
     * @param data      : 原始数据
     * @return ：返回运算结果
     */
    public byte[] rsaExternalEncrypt(RSAPubKey publicKey, byte[] data) throws AFCryptoException {
        //填充
        data = AFPkcs1Operate.pkcs1EncryptionPublicKey(publicKey.getBits(), data);
        //加密
        return cmd.rsaPublicKeyOperation(0, publicKey, Algorithm.SGD_RSA_ENC, data);
    }

    /**
     * RSA外部解密运算 私钥解密
     *
     * @param prvKey ：RSA私钥信息
     * @param data   : 加密数据
     * @return ：返回运算结果
     */
    public byte[] rsaExternalDecrypt(RSAPriKey prvKey, byte[] data) throws AFCryptoException {
        //解密
        data = cmd.rsaPrivateKeyOperation(0, prvKey, Algorithm.SGD_RSA_ENC, data);
        //去填充
        return AFPkcs1Operate.pkcs1DecryptPublicKey(prvKey.getBits(), data);
    }

    /**
     * RSA内部签名运算 私钥签名
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 原始数据
     * @return ：返回运算结果
     */

    public byte[] rsaInternalSign(int index, byte[] data) throws AFCryptoException {
        //获取私钥访问权限
        getPrivateKeyAccessRight(index, 4, "12345678");
        //获取摘要
        byte[] hash = digestForRSASign(index, -1, data);
        //填充
        byte[] bytes = AFPkcs1Operate.pkcs1EncryptionPrivate(getRSASignPublicKey(index).getBits(), hash);
        //签名
        return cmd.rsaPrivateKeyOperation(index, null, Algorithm.SGD_RSA_SIGN, bytes);
    }

    /**
     * RSA内部验证签名运算 公钥验签
     *
     * @param index      ：RSA内部密钥索引
     * @param signedData : 签名数据
     * @param rawData    : 原始数据
     * @return ：true: 验证成功，false：验证失败
     */

    public boolean rsaInternalVerify(int index, byte[] signedData, byte[] rawData) throws AFCryptoException {
        //摘要
        byte[] hash = digestForRSASign(index, -1, rawData);
        //验签 公钥解密
        byte[] bytes = cmd.rsaPublicKeyOperation(index, null, Algorithm.SGD_RSA_SIGN, signedData);
        //去填充
        bytes = AFPkcs1Operate.pkcs1DecryptionPrivate(getRSASignPublicKey(index).getBits(), bytes);
        return Arrays.equals(bytes, hash);
    }

    /**
     * RSA外部签名运算 私钥签名
     *
     * @param prvKey ：RSA私钥信息
     * @param data   : 原始数据
     * @return ：返回运算结果
     */

    public byte[] rsaExternalSign(RSAPriKey prvKey, byte[] data) throws AFCryptoException {
        //获取摘要
        byte[] hash = digestForRSASign(-1, prvKey.getBits(), data);
        //填充
        hash = AFPkcs1Operate.pkcs1EncryptionPrivate(prvKey.getBits(), hash);
        //签名 私钥加密
        return cmd.rsaPrivateKeyOperation(0, prvKey, Algorithm.SGD_RSA_SIGN, hash);
    }

    /**
     * RSA外部验证签名运算 公钥验签
     *
     * @param publicKey  ：RSA公钥信息
     * @param signedData : 签名数据
     * @param rawData    : 原始数据
     * @return ：true: 验证成功，false：验证失败
     */

    public boolean rsaExternalVerify(RSAPubKey publicKey, byte[] signedData, byte[] rawData) throws AFCryptoException {
        //摘要
        byte[] hash = digestForRSASign(-1, publicKey.getBits(), rawData);
        //验签 公钥解密
        byte[] bytes = cmd.rsaPublicKeyOperation(0, publicKey, Algorithm.SGD_RSA_SIGN, signedData);
        //去填充
        bytes = AFPkcs1Operate.pkcs1DecryptionPrivate(publicKey.getBits(), bytes);
        return Arrays.equals(bytes, hash);
    }

//=====================================================SM2计算==============================================

    /**
     * SM2内部 加密运算
     *
     * @param index 密钥索引
     * @param plain 明文数据
     * @return 密文数据
     */
    public byte[] sm2InternalEncrypt(int index, byte[] plain) throws AFCryptoException {
        //参数检查
        if (index < 0) {
            logger.error("SM2 内部密钥加密，索引不能小于0,当前索引：{}", index);
            throw new AFCryptoException("SM2 内部密钥加密，索引不能小于0,当前索引：" + index);
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM2 内部密钥加密，加密数据不能为空");
            throw new AFCryptoException("SM2 内部密钥加密，加密数据不能为空");
        }
        if (plain.length > 136) {
            logger.error("SM2 内部密钥加密，加密数据长度不能大于136,当前长度：{}", plain.length);
            throw new AFCryptoException("SM2 内部密钥加密，加密数据长度不能大于136,当前长度：" + plain.length);
        }
        return cmd.sm2Encrypt(index, null, plain);
    }

    /**
     * SM2内部 解密运算
     *
     * @param index  密钥索引
     * @param cipher 密文数据
     * @return 明文数据
     */
    public byte[] sm2InternalDecrypt(int index, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (index < 0) {
            logger.error("SM2 内部密钥解密，索引不能小于0,当前索引：{}", index);
            throw new AFCryptoException("SM2 内部密钥解密，索引不能小于0,当前索引：" + index);
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM2 内部密钥解密，解密数据不能为空");
            throw new AFCryptoException("SM2 内部密钥解密，解密数据不能为空");
        }
        //获取私钥访问权限
        getPrivateKeyAccessRight(index, 3, "12345678");
        return cmd.sm2Decrypt(index, null, cipher);
    }

    /**
     * SM2外部 加密运算
     *
     * @param pubKey 公钥信息
     * @param plain  明文数据
     * @return 密文数据
     */
    public byte[] sm2ExternalEncrypt(SM2PublicKey pubKey, byte[] plain) throws AFCryptoException {
        //参数检查
        if (pubKey == null) {
            logger.error("SM2 外部密钥加密，公钥信息不能为空");
            throw new AFCryptoException("SM2 外部密钥加密，公钥信息不能为空");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM2 外部密钥加密，加密数据不能为空");
            throw new AFCryptoException("SM2 外部密钥加密，加密数据不能为空");
        }
        return cmd.sm2Encrypt(-1, pubKey.encode(), plain);
    }

    /**
     * SM2外部 解密运算
     *
     * @param prvKey 私钥信息
     * @param cipher 密文数据
     * @return 明文数据
     */
    public byte[] sm2ExternalDecrypt(SM2PrivateKey prvKey, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (prvKey == null) {
            logger.error("SM2 外部密钥解密，私钥信息不能为空");
            throw new AFCryptoException("SM2 外部密钥解密，私钥信息不能为空");
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM2 外部密钥解密，解密数据不能为空");
            throw new AFCryptoException("SM2 外部密钥解密，解密数据不能为空");
        }
        return cmd.sm2Decrypt(-1, prvKey.encode(), cipher);
    }


    /**
     * SM2 内部密钥 签名运算 私钥签名
     *
     * @param index 密钥索引
     * @param data  原始数据
     * @return 签名数据
     */
    public byte[] sm2InternalSign(int index, byte[] data) throws AFCryptoException {
        //参数检查
        if (index < 0) {
            logger.error("SM2 内部密钥签名，索引不能小于0,当前索引：{}", index);
            throw new AFCryptoException("SM2 内部密钥签名，索引不能小于0,当前索引：" + index);
        }
        if (data == null || data.length == 0) {
            logger.error("SM2 内部密钥签名，签名数据不能为空");
            throw new AFCryptoException("SM2 内部密钥签名，签名数据不能为空");
        }
        //SM3 摘要
        byte[] digest = new cn.hutool.crypto.digest.SM3().digest(data);
        //获取私钥访问权限
        getPrivateKeyAccessRight(index, 3, "12345678");
        //签名
        return cmd.sm2Sign(index, null, digest);
    }

    /**
     * SM2 内部密钥 验签运算 公钥验签
     *
     * @param index 密钥索引
     * @param data  原始数据
     * @param sign  签名数据
     * @return 验签结果
     */
    public boolean sm2InternalVerify(int index, byte[] data, byte[] sign) throws AFCryptoException {
        //参数检查
        if (index < 0) {
            logger.error("SM2 内部密钥验签，索引不能小于0,当前索引：{}", index);
            throw new AFCryptoException("SM2 内部密钥验签，索引不能小于0,当前索引：" + index);
        }
        if (data == null || data.length == 0) {
            logger.error("SM2 内部密钥验签，验签数据不能为空");
            throw new AFCryptoException("SM2 内部密钥验签，验签数据不能为空");
        }
        if (sign == null || sign.length == 0) {
            logger.error("SM2 内部密钥验签，签名数据不能为空");
            throw new AFCryptoException("SM2 内部密钥验签，签名数据不能为空");
        }
        //SM3 摘要
        byte[] digest = new cn.hutool.crypto.digest.SM3().digest(data);
        //验签
        return cmd.sm2Verify(index, null, digest, sign);
    }

    /**
     * SM2 外部密钥 签名运算 私钥签名
     *
     * @param prvKey 私钥信息
     * @param data   原始数据
     * @return 签名数据
     */
    public byte[] sm2ExternalSign(SM2PrivateKey prvKey, byte[] data) throws AFCryptoException {
        //参数检查
        if (prvKey == null) {
            logger.error("SM2 外部密钥签名，私钥信息不能为空");
            throw new AFCryptoException("SM2 外部密钥签名，私钥信息不能为空");
        }
        if (data == null || data.length == 0) {
            logger.error("SM2 外部密钥签名，签名数据不能为空");
            throw new AFCryptoException("SM2 外部密钥签名，签名数据不能为空");
        }
        //SM3 摘要
        byte[] digest = new cn.hutool.crypto.digest.SM3().digest(data);
        //签名
        return cmd.sm2Sign(-1, prvKey.encode(), digest);
    }

    /**
     * SM2 外部密钥 验签运算 公钥验签
     *
     * @param pubKey 公钥信息
     * @param data   原始数据
     * @param sign   签名数据
     * @return 验签结果
     */
    public boolean sm2ExternalVerify(SM2PublicKey pubKey, byte[] data, byte[] sign) throws AFCryptoException {
        //参数检查
        if (pubKey == null) {
            logger.error("SM2 外部密钥验签，公钥信息不能为空");
            throw new AFCryptoException("SM2 外部密钥验签，公钥信息不能为空");
        }
        if (data == null || data.length == 0) {
            logger.error("SM2 外部密钥验签，验签数据不能为空");
            throw new AFCryptoException("SM2 外部密钥验签，验签数据不能为空");
        }
        if (sign == null || sign.length == 0) {
            logger.error("SM2 外部密钥验签，签名数据不能为空");
            throw new AFCryptoException("SM2 外部密钥验签，签名数据不能为空");
        }
        //SM3 摘要
        byte[] digest = new cn.hutool.crypto.digest.SM3().digest(data);
        //验签
        return cmd.sm2Verify(-1, pubKey.encode(), digest, sign);
    }


    //======================================================对称加密======================================================

    /**
     * SM4 ECB 内部密钥加密
     *
     * @param keyIndex 密钥索引
     * @param plain    原始数据
     * @return 加密数据
     */
    public byte[] sm4InternalEncryptECB(int keyIndex, byte[] plain) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM4 加密，加密数据不能为空");
            throw new AFCryptoException("SM4 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SMS4_ECB, 1, keyIndex, null, null, bytes.get(i));
            bytes.set(i, encrypt);
        }
        //合并数据
        return mergePackage(bytes);
    }


    /**
     * SM4 ECB 外部密钥加密
     *
     * @param key   密钥信息
     * @param plain 原始数据
     * @return 加密数据
     */
    public byte[] sm4ExternalEncryptECB(byte[] key, byte[] plain) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM4 加密，密钥信息不能为空");
            throw new AFCryptoException("SM4 加密，密钥信息不能为空");
        }
        if (key.length != 16) {
            logger.error("SM4 加密，密钥长度必须为16字节");
            throw new AFCryptoException("SM4 加密，密钥长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM4 加密，加密数据不能为空");
            throw new AFCryptoException("SM4 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SMS4_ECB, 0, 0, key, null, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM4 ECB 密钥句柄加密
     */
    public byte[] sm4HandleEncryptECB(int keyHandle, byte[] plain) throws AFCryptoException {
        //参数检查
        if (plain == null || plain.length == 0) {
            logger.error("SM4 加密，加密数据不能为空");
            throw new AFCryptoException("SM4 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SMS4_ECB, 2, keyHandle, null, null, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }


    /**
     * SM4 CBC 内部密钥加密
     *
     * @param keyIndex 密钥索引
     * @param iv       初始向量
     * @param plain    原始数据
     * @return 加密数据
     */
    public byte[] sm4InternalEncryptCBC(int keyIndex, byte[] iv, byte[] plain) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (iv == null || iv.length == 0) {
            logger.error("SM4 加密，初始向量不能为空");
            throw new AFCryptoException("SM4 加密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM4 加密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM4 加密，初始向量长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM4 加密，加密数据不能为空");
            throw new AFCryptoException("SM4 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SMS4_CBC, 1, keyIndex, null, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM4 CBC 外部密钥加密
     *
     * @param key   密钥信息
     * @param iv    初始向量
     * @param plain 原始数据
     * @return 加密数据
     */
    public byte[] sm4ExternalEncryptCBC(byte[] key, byte[] iv, byte[] plain) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM4 加密，密钥信息不能为空");
            throw new AFCryptoException("SM4 加密，密钥信息不能为空");
        }
        if (key.length != 16) {
            logger.error("SM4 加密，密钥长度必须为16字节");
            throw new AFCryptoException("SM4 加密，密钥长度必须为16字节");
        }
        if (iv == null || iv.length == 0) {
            logger.error("SM4 加密，初始向量不能为空");
            throw new AFCryptoException("SM4 加密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM4 加密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM4 加密，初始向量长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM4 加密，加密数据不能为空");
            throw new AFCryptoException("SM4 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SMS4_CBC, 0, 0, key, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }


    /**
     * SM4 CBC 密钥句柄加密
     */
    public byte[] sm4HandleEncryptCBC(int keyHandle, byte[] iv, byte[] plain) throws AFCryptoException {
        //参数检查
        if (iv == null || iv.length == 0) {
            logger.error("SM4 加密，初始向量不能为空");
            throw new AFCryptoException("SM4 加密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM4 加密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM4 加密，初始向量长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM4 加密，加密数据不能为空");
            throw new AFCryptoException("SM4 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SMS4_CBC, 2, keyHandle, null, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM1 内部加密 ECB
     */
    public byte[] sm1InternalEncryptECB(int keyIndex, byte[] plain) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM1 加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM1 加密，加密数据不能为空");
            throw new AFCryptoException("SM1 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM1_ECB, 1, keyIndex, null, null, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }


    /**
     * SM1 外部加密 ECB
     */
    public byte[] sm1ExternalEncryptECB(byte[] key, byte[] plain) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM1 加密，密钥信息不能为空");
            throw new AFCryptoException("SM1 加密，密钥信息不能为空");
        }
        if (key.length != 16) {
            logger.error("SM1 加密，密钥长度必须为16字节");
            throw new AFCryptoException("SM1 加密，密钥长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM1 加密，加密数据不能为空");
            throw new AFCryptoException("SM1 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM1_ECB, 0, 0, key, null, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM1 密钥句柄加密 ECB
     */
    public byte[] sm1HandleEncryptECB(int keyHandle, byte[] plain) throws AFCryptoException {
        //参数检查
        if (plain == null || plain.length == 0) {
            logger.error("SM1 加密，加密数据不能为空");
            throw new AFCryptoException("SM1 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM1_ECB, 2, keyHandle, null, null, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM1 内部加密 CBC
     */
    public byte[] sm1InternalEncryptCBC(int keyIndex, byte[] iv, byte[] plain) throws AFCryptoException {
        //参数检查

        if (iv == null || iv.length == 0) {
            logger.error("SM1 加密，初始向量不能为空");
            throw new AFCryptoException("SM1 加密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM1 加密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM1 加密，初始向量长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM1 加密，加密数据不能为空");
            throw new AFCryptoException("SM1 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM1_CBC, 1, keyIndex, null, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM1 外部加密 CBC
     */
    public byte[] sm1ExternalEncryptCBC(byte[] key, byte[] iv, byte[] plain) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM1 加密，密钥信息不能为空");
            throw new AFCryptoException("SM1 加密，密钥信息不能为空");
        }
        if (key.length != 16) {
            logger.error("SM1 加密，密钥长度必须为16字节");
            throw new AFCryptoException("SM1 加密，密钥长度必须为16字节");
        }
        if (iv == null || iv.length == 0) {
            logger.error("SM1 加密，初始向量不能为空");
            throw new AFCryptoException("SM1 加密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM1 加密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM1 加密，初始向量长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM1 加密，加密数据不能为空");
            throw new AFCryptoException("SM1 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM1_CBC, 0, 0, key, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM1 密钥句柄加密 CBC
     */
    public byte[] sm1HandleEncryptCBC(int keyHandle, byte[] iv, byte[] plain) throws AFCryptoException {
        //参数检查

        if (iv == null || iv.length == 0) {
            logger.error("SM1 加密，初始向量不能为空");
            throw new AFCryptoException("SM1 加密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM1 加密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM1 加密，初始向量长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM1 加密，加密数据不能为空");
            throw new AFCryptoException("SM1 加密，加密数据不能为空");
        }
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM1_CBC, 2, keyHandle, null, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    //======================================================对称解密======================================================

    /**
     * SM4 内部密钥 解密 ECB
     */
    public byte[] sm4InternalDecryptECB(int keyIndex, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 解密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 解密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM4 解密，加密数据不能为空");
            throw new AFCryptoException("SM4 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SMS4_ECB, 1, keyIndex, null, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));

    }

    /**
     * SM4 外部密钥 解密 ECB
     */
    public byte[] sm4ExternalDecryptECB(byte[] key, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM4 解密，密钥信息不能为空");
            throw new AFCryptoException("SM4 解密，密钥信息不能为空");
        }
        if (key.length != 16) {
            logger.error("SM4 解密，密钥长度必须为16字节");
            throw new AFCryptoException("SM4 解密，密钥长度必须为16字节");
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM4 解密，加密数据不能为空");
            throw new AFCryptoException("SM4 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SMS4_ECB, 0, -1, key, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 密钥句柄 解密 ECB
     */
    public byte[] sm4HandleDecryptECB(int keyHandle, byte[] cipher) throws AFCryptoException {
        //参数检查

        if (cipher == null || cipher.length == 0) {
            logger.error("SM4 解密，加密数据不能为空");
            throw new AFCryptoException("SM4 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SMS4_ECB, 2, keyHandle, null, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 内部密钥 解密 CBC
     */
    public byte[] sm4InternalDecryptCBC(int keyIndex, byte[] iv, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 解密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 解密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (iv == null || iv.length == 0) {
            logger.error("SM4 解密，初始向量不能为空");
            throw new AFCryptoException("SM4 解密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM4 解密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM4 解密，初始向量长度必须为16字节");
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM4 解密，加密数据不能为空");
            throw new AFCryptoException("SM4 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SMS4_CBC, 1, keyIndex, null, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 外部密钥 解密 CBC
     */
    public byte[] sm4ExternalDecryptCBC(byte[] key, byte[] iv, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM4 解密，密钥信息不能为空");
            throw new AFCryptoException("SM4 解密，密钥信息不能为空");
        }
        if (key.length != 16) {
            logger.error("SM4 解密，密钥长度必须为16字节");
            throw new AFCryptoException("SM4 解密，密钥长度必须为16字节");
        }
        if (iv == null || iv.length == 0) {
            logger.error("SM4 解密，初始向量不能为空");
            throw new AFCryptoException("SM4 解密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM4 解密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM4 解密，初始向量长度必须为16字节");
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM4 解密，加密数据不能为空");
            throw new AFCryptoException("SM4 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SMS4_CBC, 0, -1, key, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 密钥句柄 解密 CBC
     */
    public byte[] sm4HandleDecryptCBC(int keyHandle, byte[] iv, byte[] cipher) throws AFCryptoException {
        //参数检查

        if (iv == null || iv.length == 0) {
            logger.error("SM4 解密，初始向量不能为空");
            throw new AFCryptoException("SM4 解密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM4 解密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM4 解密，初始向量长度必须为16字节");
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM4 解密，加密数据不能为空");
            throw new AFCryptoException("SM4 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SMS4_CBC, 2, keyHandle, null, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM1 内部解密 ECB
     */
    public byte[] sm1InternalDecryptECB(int keyIndex, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 解密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM1 解密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM1 解密，加密数据不能为空");
            throw new AFCryptoException("SM1 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM1_ECB, 1, keyIndex, null, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM1 外部解密 ECB
     */
    public byte[] sm1ExternalDecryptECB(byte[] key, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM1 解密，密钥信息不能为空");
            throw new AFCryptoException("SM1 解密，密钥信息不能为空");
        }
        if (key.length != 16) {
            logger.error("SM1 解密，密钥长度必须为16字节");
            throw new AFCryptoException("SM1 解密，密钥长度必须为16字节");
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM1 解密，加密数据不能为空");
            throw new AFCryptoException("SM1 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM1_ECB, 0, -1, key, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM1 密钥句柄 解密 ECB
     */
    public byte[] sm1HandleDecryptECB(int keyHandle, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (cipher == null || cipher.length == 0) {
            logger.error("SM1 解密，加密数据不能为空");
            throw new AFCryptoException("SM1 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM1_ECB, 2, keyHandle, null, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM1 内部解密 CBC
     */
    public byte[] sm1InternalDecryptCBC(int keyIndex, byte[] iv, byte[] plain) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 解密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM1 解密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (iv == null || iv.length == 0) {
            logger.error("SM1 解密，初始向量不能为空");
            throw new AFCryptoException("SM1 解密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM1 解密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM1 解密，初始向量长度必须为16字节");
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM1 解密，加密数据不能为空");
            throw new AFCryptoException("SM1 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM1_CBC, 1, keyIndex, null, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));

    }

    /**
     * SM1 外部解密 CBC
     */
    public byte[] sm1ExternalDecryptCBC(byte[] key, byte[] iv, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM1 解密，密钥信息不能为空");
            throw new AFCryptoException("SM1 解密，密钥信息不能为空");
        }
        if (key.length != 16) {
            logger.error("SM1 解密，密钥长度必须为16字节");
            throw new AFCryptoException("SM1 解密，密钥长度必须为16字节");
        }
        if (iv == null || iv.length == 0) {
            logger.error("SM1 解密，初始向量不能为空");
            throw new AFCryptoException("SM1 解密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM1 解密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM1 解密，初始向量长度必须为16字节");
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM1 解密，加密数据不能为空");
            throw new AFCryptoException("SM1 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM1_CBC, 0, -1, key, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM1 密钥句柄 解密 CBC
     */
    public byte[] sm1HandleDecryptCBC(int keyHandle, byte[] iv, byte[] cipher) throws AFCryptoException {
        //参数检查
        if (iv == null || iv.length == 0) {
            logger.error("SM1 解密，初始向量不能为空");
            throw new AFCryptoException("SM1 解密，初始向量不能为空");
        }
        if (iv.length != 16) {
            logger.error("SM1 解密，初始向量长度必须为16字节");
            throw new AFCryptoException("SM1 解密，初始向量长度必须为16字节");
        }
        if (cipher == null || cipher.length == 0) {
            logger.error("SM1 解密，加密数据不能为空");
            throw new AFCryptoException("SM1 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM1_CBC, 2, keyHandle, null, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }
    //======================================================批量加密======================================================

    /**
     * SM4 内部批量加密 ECB
     */
    public List<byte[]> sm4InternalBatchEncryptECB(int keyIndex, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 批量加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 批量加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (plainList == null || plainList.size() == 0) {
            logger.error("SM4 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM4 批量加密，加密数据不能为空");
        }
        //list 总长度<2M
        int totalLength = plainList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }

        //padding
        plainList = plainList.stream()
                .map(AFHsmDevice::padding)
                .collect(Collectors.toList());

        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SMS4_ECB, 1, keyIndex, null, null, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        return IntStream.range(0, count)
                .mapToObj(i -> buf.readOneData())
                .collect(Collectors.toList());
    }
    /**
     * SM4外部批量加密 ECB
     */
    public List<byte[]> sm4ExternalBatchEncryptECB(byte[] keyIndex, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (keyIndex == null || keyIndex.length == 0) {
            logger.error("SM4 批量加密，索引不能为空");
            throw new AFCryptoException("SM4 批量加密，索引不能为空");
        }
        if (plainList == null || plainList.size() == 0) {
            logger.error("SM4 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM4 批量加密，加密数据不能为空");
        }
        int totalLength = plainList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SMS4_ECB, 0, 0, keyIndex, null, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        return IntStream.range(0, count)
                .mapToObj(i -> buf.readOneData())
                .collect(Collectors.toList());
    }




    //======================================================批量解密======================================================

    /**
     * SM4 内部批量解密 ECB
     */


    /**
     * SM3哈希 杂凑算法 <br>
     * 带公钥信息和用户ID
     *
     * @param data      待杂凑数据
     * @param publicKey 公钥 可以传入256/512位公钥 实际计算使用256位公钥
     * @param userID    用户ID
     * @return 杂凑值
     * 杂凑异常
     */

    public byte[] sm3HashWithPubKey(byte[] data, SM2PublicKey publicKey, byte[] userID) throws AFCryptoException {
        SM2PublicKey publicKey256 = publicKey.to256();
        return sm3.SM3HashWithPublicKey256(data, publicKey256, userID);
    }


    //============================================================工具============================================================


    /**
     * 获取私钥访问权限
     *
     * @param keyIndex 密钥索引
     * @param keyType  密钥类型 4:RSA; 3:SM2;
     * @param passwd   私钥访问权限口令
     */
    private void getPrivateKeyAccessRight(int keyIndex, int keyType, String passwd) throws AFCryptoException {
        logger.info("获取获取私钥访问权限 keyIndex:{}, keyType:{}, passwd:{}", keyIndex, keyType, passwd);
        cmd.getPrivateAccess(keyIndex, keyType, passwd);
    }


    /**
     * 合并数组
     *
     * @param bytes 数组集合
     * @return 合并后的数组
     */
    private byte[] mergePackage(List<byte[]> bytes) {
        int length = 0;
        for (byte[] aByte : bytes) {
            length += aByte.length;
        }
        byte[] result = new byte[length];
        int index = 0;
        for (byte[] aByte : bytes) {
            System.arraycopy(aByte, 0, result, index, aByte.length);
            index += aByte.length;
        }
        return result;
    }

    /**
     * RSA签名验签 摘要运算 private 非API
     *
     * @param index   ：RSA内部密钥索引 如果是外部密钥，传-1
     * @param length: 模长 如果是内部密钥，传-1
     * @param data    : 原始数据
     * @return ：digest数据
     */
    private byte[] digestForRSASign(int index, int length, byte[] data) throws AFCryptoException {
        logger.info("RSA签名 摘要计算 index:{},priKey:{}", index, length);
        //获取公钥模长
        int bits;
        if (index > 0 && length == -1) { //内部密钥
            RSAPubKey pubKey = getRSASignPublicKey(index);
            bits = pubKey.getBits();
        } else if (-1 == index && length != -1) { //外部密钥
            bits = length;
        } else {
            logger.error("RSA签名摘要失败,参数错误,index:{},length:{}", index, length);
            throw new AFCryptoException("RSA签名失败,参数错误,index:" + index + ",length:" + length);
        }
        logger.info("RSA签名 摘要计算 当前模长:{}", bits);
        //摘要算法
        String algorithm = "";
        if (bits == 1024) {
            algorithm = "SHA-1";
        } else if (bits == 2048) {
            algorithm = "SHA-256";
        } else {
            logger.error("RSA签名失败,公钥模长错误,bits(1024|2048):{}", bits);
            throw new AFCryptoException("RSA签名失败,公钥模长错误,bits(1024|2048):" + bits);
        }

        //摘要
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            logger.error("RSA内部签名失败,摘要失败,摘要算法:{}", algorithm);
            throw new RuntimeException("RSA内部签名失败,摘要失败,摘要算法:" + algorithm);
        }
        return md.digest(data);
    }

    /**
     * 填充
     * 补齐为16的倍数
     *
     * @param data 待填充数据
     * @return 填充后数据
     */
    private static byte[] padding(byte[] data) {
        int paddingNumber = 16 - (data.length % 16);
        byte[] paddingData = new byte[paddingNumber];
        Arrays.fill(paddingData, (byte) paddingNumber);
        byte[] outData = new byte[data.length + paddingNumber];
        System.arraycopy(data, 0, outData, 0, data.length);
        System.arraycopy(paddingData, 0, outData, data.length, paddingNumber);
        return outData;
    }

//    private static byte[] padding(byte[] data) {
////        if ((data.length % 16) == 0) {
////            return data;
////        }
//        int paddingNumber = 16 - (data.length % 16);
//        byte[] paddingData = new byte[paddingNumber];
//        Arrays.fill(paddingData, (byte) paddingNumber);
//        byte[] outData = new byte[data.length + paddingNumber];
//        System.arraycopy(data, 0, outData, 0, data.length);
//        System.arraycopy(paddingData, 0, outData, data.length, paddingNumber);
//        return outData;
//    }


    /**
     * 去填充
     *
     * @param data 待去填充数据
     * @return 去填充后数据
     * 去填充异常
     */
    private static byte[] cutting(byte[] data) throws AFCryptoException {
        int paddingNumber = Byte.toUnsignedInt(data[data.length - 1]);
        for (int i = 0; i < paddingNumber; ++i) {
            if ((int) data[data.length - paddingNumber + i] != paddingNumber) {
                throw new AFCryptoException("验证填充数据错误");
            }
        }
        byte[] outData = new byte[data.length - paddingNumber];
        System.arraycopy(data, 0, outData, 0, data.length - paddingNumber);
        return outData;
    }
//    private static byte[] cutting(byte[] data) {
//        int paddingNumber = Byte.toUnsignedInt(data[data.length - 1]);
//        if (paddingNumber >= 16) paddingNumber = 0;
//        for (int i = 0; i < paddingNumber; ++i) {
//            if ((int) data[data.length - paddingNumber + i] != paddingNumber) {
//                return null;
//            }
//        }
//        byte[] outData = new byte[data.length - paddingNumber];
//        System.arraycopy(data, 0, outData, 0, data.length - paddingNumber);
//        return outData;
//    }
}
