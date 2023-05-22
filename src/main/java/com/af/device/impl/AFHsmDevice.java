package com.af.device.impl;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.*;
import com.af.crypto.algorithm.sm1.SM1;
import com.af.crypto.algorithm.sm1.SM1Impl;
import com.af.crypto.algorithm.sm2.SM2;
import com.af.crypto.algorithm.sm2.SM2Impl;
import com.af.crypto.algorithm.sm3.SM3;
import com.af.crypto.algorithm.sm3.SM3Impl;
import com.af.crypto.algorithm.sm4.SM4;
import com.af.crypto.algorithm.sm4.SM4Impl;
import com.af.crypto.key.keyInfo.AFKmsKeyInfo;
import com.af.crypto.key.keyInfo.AFSymmetricKeyStatus;
import com.af.crypto.key.keyInfo.KeyInfo;
import com.af.crypto.key.keyInfo.KeyInfoImpl;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.crypto.struct.impl.sm2.SM2Cipher;
import com.af.crypto.struct.impl.sm2.SM2Signature;
import com.af.device.DeviceInfo;
import com.af.device.IAFHsmDevice;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description HSM设备实现类 用于实现HSM设备的各种算法 以及获取设备信息<br>
 * 该类为单例模式 通过getInstance方法获取实例<br>
 * 该层为对外接口层 用于对外提供各种算法的实现,实际message在具体算法实现类中构造<br>
 * 该层进行参数校验,具体调用在各个密码算法的实现中(获取设备信息和随机数在当前类中执行)<br>
 * @since 2023/4/27 14:53
 */
public class AFHsmDevice implements IAFHsmDevice {
    private static final Logger logger = LoggerFactory.getLogger(AFHsmDevice.class);
    private byte[] agKey = null;  //协商密钥
    //set agKey

    @Getter
    private static AFNettyClient client;  //netty客户端
    private final SM1 sm1 = new SM1Impl(client);
    private final SM2 sm2 = new SM2Impl(client);
    private final SM3 sm3 = new SM3Impl(client);
    private final SM4 sm4 = new SM4Impl(client);
    private final KeyInfo keyInfo = KeyInfoImpl.getInstance(client);

    //==============================单例模式===================================
    protected AFHsmDevice() {
    }

    private static final class InstanceHolder {
        static final AFHsmDevice instance = new AFHsmDevice();
    }

    public static AFHsmDevice getInstance(String host, int port, String passwd) {
        client = AFNettyClient.getInstance(host, port, passwd);
        return InstanceHolder.instance;
    }

    public AFHsmDevice setAgKey() {
        this.agKey = this.keyAgreement(client);
        return this;
    }
    //==============================API===================================

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * @throws AFCryptoException 获取设备信息异常
     */
    @Override
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        logger.info("获取设备信息");
        RequestMessage req = new RequestMessage(CMDCode.CMD_DEVICEINFO, null);
        //发送请求
        ResponseMessage resp = client.send(req);
        if (resp == null || resp.getHeader().getErrorCode() != 0) {
            logger.error("获取设备信息错误,无响应或者响应码错误 response:{} ErrorCode:{}", resp == null ? "null" : resp.toString(), resp == null ? "null" : resp.getHeader().getErrorCode());
            throw new AFCryptoException("获取设备信息错误");
        }
        //解析响应

        DeviceInfo info = new DeviceInfo();
        info.decode(resp.getDataBuffer().readOneData());
        return info;
    }


    /**
     * 获取随机数
     *
     * @param length 随机数长度 字节数
     * @return 随机数
     * @throws AFCryptoException 获取随机数异常
     */
    @Override
    public byte[] getRandom(int length) throws AFCryptoException {
        logger.info("获取随机数");
        if (length <= 0) {
            logger.error("获取随机数错误,随机数长度错误 length:{}", length);
            throw new AFCryptoException("获取随机数错误,随机数长度错误");
        }
        byte[] param = new BytesBuffer().append(length).toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATERANDOM, param);
        ResponseMessage resp;
        //发送请求
        try {
            resp = client.send(req);
        } catch (Exception e) {
            logger.error("获取随机数错误", e);
            throw new AFCryptoException("获取随机数异常", e);
        }
        if (resp == null || resp.getHeader().getErrorCode() != 0) {
            logger.error("获取随机数错误,无响应或者响应码错误 response:{} ErrorCode:{}", resp == null ? "null" : resp.toString(), resp == null ? "null" : resp.getHeader().getErrorCode());
            throw new AFCryptoException("获取随机数异常");
        }
        int retLen = BytesOperate.bytes2int(resp.getData());
        return BytesOperate.subBytes(resp.getData(), 4, retLen);
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
        byte[] paddingData = Padding(data);
        List<byte[]> bytes = new ArrayList<>();
        //分段加密 4096个字节一段 n-1段
        for (uiIndex = 0; uiIndex != (paddingData.length / ConstantNumber.AF_LEN_4096); ++uiIndex) {
            inputData = new byte[ConstantNumber.AF_LEN_4096];
            System.arraycopy(paddingData, ConstantNumber.AF_LEN_4096 * uiIndex, inputData, 0, ConstantNumber.AF_LEN_4096);
            bytes.add(inputData);
        }
        //最后一段 如果不足4096个字节
        if ((paddingData.length % ConstantNumber.AF_LEN_4096) != 0) {
            inputData = new byte[paddingData.length % ConstantNumber.AF_LEN_4096];
            System.arraycopy(paddingData, ConstantNumber.AF_LEN_4096 * uiIndex, inputData, 0, inputData.length);
            bytes.add(inputData);
        }
        return bytes;
    }

    /**
     * SM1内部密钥加密
     *
     * @param mode  分组模式 ECB/CBC
     * @param index 内部密钥索引 如果使用外部密钥传-1
     * @param iv    初始向量  CBC模式下需要 ECB模式下传null
     * @param data  待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] SM1Encrypt(GroupMode mode, int index, byte[] iv, byte[] data) throws AFCryptoException {
        List<byte[]> singleData = splitPackage(data); //分包
        BytesBuffer buffer = new BytesBuffer();
        switch (mode) {
            case ECB:
                for (byte[] bytes : singleData) {
                    buffer.append(sm1.SM1EncryptECB(index, bytes));
                }
                break;
            case CBC:
                for (byte[] bytes : singleData) {
                    buffer.append(sm1.SM1EncryptCBC(index, iv, bytes));
                }
                break;
            default:
                break;
        }
        return buffer.toBytes();

    }


    /**
     * SM1内部密钥解密
     *
     * @param mode  分组模式 ECB/CBC
     * @param index 内部密钥索引
     * @param iv    初始向量  CBC模式下需要 ECB模式下传null
     * @param data  待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM1Decrypt(GroupMode mode, int index, byte[] iv, byte[] data) throws AFCryptoException {
        List<byte[]> groupData = splitPackage(data); //分组
        BytesBuffer buffer = new BytesBuffer();
        switch (mode) {
            case ECB:
                for (byte[] bytes : groupData) {
                    //解密后的数据需要去除填充
                    buffer.append(sm1.SM1DecryptECB(index, bytes));
                }
                break;
            case CBC:
                for (byte[] bytes : groupData) {
                    //解密后的数据需要去除填充
                    buffer.append(sm1.SM1DecryptCBC(index, iv, bytes));
                }
                break;
            default:
                break;
        }
        return cutting(buffer.toBytes());
    }

    /**
     * SM1外部密钥加密
     *
     * @param mode 分组模式 ECB/CBC
     * @param key  密钥
     * @param iv   初始向量  CBC模式下需要 ECB模式下传null
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] SM1Encrypt(GroupMode mode, byte[] key, byte[] iv, byte[] data) throws AFCryptoException {
        List<byte[]> singleData = splitPackage(data); //分包
        BytesBuffer buffer = new BytesBuffer();
        switch (mode) {
            case ECB:
                for (byte[] bytes : singleData) {
                    buffer.append(sm1.SM1EncryptECB(key, bytes));
                }
                break;
            case CBC:
                for (byte[] bytes : singleData) {
                    buffer.append(sm1.SM1EncryptCBC(key, iv, bytes));
                }
                break;
            default:
                break;
        }
        return buffer.toBytes();

    }

    /**
     * SM1外部密钥解密
     *
     * @param mode       分组模式 ECB/CBC
     * @param key        密钥
     * @param iv         初始向量  CBC模式下需要 ECB模式下传null
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM1Decrypt(GroupMode mode, byte[] key, byte[] iv, byte[] encodeData) throws AFCryptoException {
        List<byte[]> singleData = splitPackage(encodeData); //分包
        BytesBuffer buffer = new BytesBuffer();
        switch (mode) {
            case ECB:
                for (byte[] bytes : singleData) {
                    //解密后的数据需要去除填充
                    buffer.append(sm1.SM1DecryptECB(key, bytes));
                }
                break;
            case CBC:
                for (byte[] bytes : singleData) {
                    //解密后的数据需要去除填充
                    buffer.append(sm1.SM1DecryptCBC(key, iv, bytes));
                }
                break;
            default:
                break;
        }
        return cutting(buffer.toBytes());
    }

    /**
     * 获取SM2签名公钥
     *
     * @param index  索引
     * @param length 模长 256/512
     * @return SM2签名公钥
     * @throws AFCryptoException 获取SM2签名公钥异常
     */
    @Override
    public SM2PublicKey getSM2SignPublicKey(int index, ModulusLength length) throws AFCryptoException {
        if (index < 1 || index > ConstantNumber.MAX_ECC_KEY_PAIR_COUNT) {
            logger.error("用户指定的SM2公钥索引错误, 索引范围为[1, {}],当前指定索引为: {}", ConstantNumber.MAX_ECC_KEY_PAIR_COUNT, index);
            throw new AFCryptoException("用户指定的SM2公钥索引错误,当前指定索引为: " + index);
        }
        SM2PublicKey publicKey = sm2.getPublicKey(index, SM2KeyType.SIGN);
        if (ModulusLength.LENGTH_256.equals(length)) {
            return publicKey.to256();
        }
        return publicKey;
    }

    /**
     * 获取SM2加密公钥
     *
     * @param index 索引
     * @return SM2加密公钥 默认512位, 如果需要256位, 请调用{@link SM2PublicKey#to256()}
     * @throws AFCryptoException 获取SM2加密公钥异常
     */
    @Override
    public SM2PublicKey getSM2EncryptPublicKey(int index, ModulusLength length) throws AFCryptoException {
        logger.info("获取SM2加密公钥 index: {} length: {}", index, length);
        if (index < 1 || index > ConstantNumber.MAX_ECC_KEY_PAIR_COUNT) {
            logger.error("用户指定的SM2公钥索引错误, 索引范围为[1, {}],当前指定索引为: {}", ConstantNumber.MAX_ECC_KEY_PAIR_COUNT, index);
            throw new AFCryptoException("用户指定的SM2公钥索引错误,当前指定索引为: " + index);
        }
        SM2PublicKey publicKey = sm2.getPublicKey(index, SM2KeyType.ENCRYPT);
        if (ModulusLength.LENGTH_256.equals(length)) {
            return publicKey.to256();
        }
        return publicKey;
    }

    /**
     * 生成SM2密钥对
     *
     * @return SM2密钥对 默认512位, 如果需要256位, 请调用{@link SM2KeyPair#to256()}
     * @throws AFCryptoException 生成SM2密钥对异常
     */
    @Override
    public SM2KeyPair generateSM2KeyPair(ModulusLength length) throws AFCryptoException {
        logger.info("生成SM2密钥对");
        SM2KeyPair keyPair = sm2.generateKeyPair();
        if (ModulusLength.LENGTH_256.equals(length)) {
            return keyPair.to256();
        }
        return keyPair;
    }

    /**
     * SM2内部密钥加密
     *
     * @param index 索引
     * @param data  待加密数据
     * @return 加密后的SM2Cipher对象 默认512位, 如果需要256位, 请调用{@link SM2Cipher#to256()}
     * @throws AFCryptoException 加密异常
     */
    @Override
    public SM2Cipher SM2Encrypt(ModulusLength length, int index, byte[] data) throws AFCryptoException {
        logger.info("SM2内部密钥加密 index: {} length: {}", index, length);
        if (index < 1 || index > ConstantNumber.MAX_ECC_KEY_PAIR_COUNT) {
            logger.error("用户指定的SM2公钥索引错误, 索引范围为[1, {}],当前指定索引为: {}", ConstantNumber.MAX_ECC_KEY_PAIR_COUNT, index);
            throw new AFCryptoException("用户指定的SM2公钥索引错误,当前指定索引为: " + index);
        }
        byte[] encData = sm2.sm2Encrypt(index, null, data);
        SM2Cipher cipher = new SM2Cipher(encData);
        if (ModulusLength.LENGTH_256.equals(length)) {
            return cipher.to256();
        }
        return cipher;
    }

    /**
     * SM2内部密钥解密
     *
     * @param index      索引
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM2Decrypt(ModulusLength length, int index, SM2Cipher encodeData) throws AFCryptoException {
        logger.info("SM2内部密钥解密 length: {} index: {} encodeData: {}", length, index, encodeData);
        if (index < 1 || index > ConstantNumber.MAX_ECC_KEY_PAIR_COUNT) {
            logger.error("用户指定的SM2公钥索引错误, 索引范围为[1, {}],当前指定索引为: {}", ConstantNumber.MAX_ECC_KEY_PAIR_COUNT, index);
            throw new AFCryptoException("用户指定的SM2公钥索引错误,当前指定索引为: " + index);
        }
        if (ModulusLength.LENGTH_256.equals(length) && 256 == encodeData.getLength()) {
            encodeData = encodeData.to512();//转换为512位 , 服务端只处理512位
        }
        return sm2.SM2Decrypt(index, null, encodeData);
    }

    /**
     * SM2外部密钥加密
     *
     * @param key  密钥
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public SM2Cipher SM2Encrypt(ModulusLength length, SM2PublicKey key, byte[] data) throws AFCryptoException {
        logger.info("SM2外部密钥加密 length: {} key: {} data: {}", length, key, data);
        key = key.to256();
        byte[] bytes = sm2.sm2Encrypt(0, key, data);
        SM2Cipher sm2Cipher = new SM2Cipher(bytes);
        if (ModulusLength.LENGTH_256.equals(length)) {
            return sm2Cipher.to256();
        }
        return sm2Cipher;
    }

    /**
     * SM2外部密钥解密
     *
     * @param key        密钥
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM2Decrypt(ModulusLength length, SM2PrivateKey key, SM2Cipher encodeData) throws AFCryptoException {
        logger.info("SM2外部密钥解密 length: {} key: {} encodeData: {}", length, key, encodeData);
        key = key.to256();
        encodeData = encodeData.to256();
        return sm2.SM2Decrypt(0, key, encodeData);
    }

    /**
     * SM2 内部密钥签名
     *
     * @param length 模量长度 256/512
     * @param index  密钥索引
     * @param data   待签名数据
     * @throws AFCryptoException 签名异常
     */
    @Override
    public SM2Signature SM2Signature(ModulusLength length, int index, byte[] data) throws AFCryptoException {
        logger.info("SM2内部密钥签名 index: {} data: {}", index, data);
        if (index < 1 || index > ConstantNumber.MAX_ECC_KEY_PAIR_COUNT) {
            logger.error("用户指定的SM2公钥索引错误, 索引范围为[1, {}],当前指定索引为: {}", ConstantNumber.MAX_ECC_KEY_PAIR_COUNT, index);
            throw new AFCryptoException("用户指定的SM2公钥索引错误,当前指定索引为: " + index);
        }
        byte[] sign = sm2.SM2Sign(index, null, data);
        SM2Signature sm2Signature = new SM2Signature(sign);
        if (ModulusLength.LENGTH_256.equals(length)) {
            return sm2Signature.to256();
        }
        return sm2Signature;
    }

    /**
     * SM2 内部密钥验签
     *
     * @param length    模量长度 256/512
     * @param index     密钥索引 0-1023
     * @param data      待验签数据
     * @param signature 签名
     * @return 验签结果 true:验签成功 false:验签失败
     * @throws AFCryptoException 验签异常
     */
    @Override
    public boolean SM2Verify(ModulusLength length, int index, byte[] data, SM2Signature signature) throws AFCryptoException {
        logger.info("SM2内部密钥验签 length: {} index: {} data: {} signature: {}", length, index, data, signature);
        if (index < 1 || index > ConstantNumber.MAX_ECC_KEY_PAIR_COUNT) {
            logger.error("用户指定的SM2公钥索引错误, 索引范围为[1, {}],当前指定索引为: {}", ConstantNumber.MAX_ECC_KEY_PAIR_COUNT, index);
            throw new AFCryptoException("用户指定的SM2公钥索引错误,当前指定索引为: " + index);
        }
        // 如果是256模量长度,则转换为512模量长度 后端只以512模量长度验签
        if (ModulusLength.LENGTH_256.equals(length)) {
            signature = signature.to512();
        }
        return sm2.SM2Verify(index, null, data, signature.encode());

    }

    /**
     * SM2 外部密钥签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return 签名
     * @throws AFCryptoException 签名异常
     */
    @Override
    public SM2Signature SM2Signature(ModulusLength length, byte[] data, SM2PrivateKey privateKey) throws AFCryptoException {
        logger.info("SM2外部密钥签名 data: {} privateKey: {}", data, privateKey);
        if (ModulusLength.LENGTH_256.equals(length)) {
            privateKey = privateKey.to256();
        }
        if (ModulusLength.LENGTH_512.equals(length)) {
            privateKey = privateKey.to512();
        }
        byte[] sign = sm2.SM2Sign(-1, privateKey, data);
        SM2Signature sm2Signature = new SM2Signature(sign);
        if (ModulusLength.LENGTH_256.equals(length)) {
            return sm2Signature.to256();
        } else {
            return sm2Signature;
        }
    }

    /**
     * SM2 外部密钥验签
     *
     * @param data      待验签数据
     * @param signature 签名
     * @param publicKey 公钥
     * @return 验签结果 true:验签成功 false:验签失败
     * @throws AFCryptoException 验签异常
     */
    @Override
    public boolean SM2Verify(ModulusLength length, byte[] data, SM2Signature signature, SM2PublicKey publicKey) throws AFCryptoException {
        logger.info("SM2外部密钥验签 data: {} signature: {} publicKey: {}", data, signature, publicKey);
        if (ModulusLength.LENGTH_256.equals(length)) {
            publicKey = publicKey.to256();
        }
        if (ModulusLength.LENGTH_512.equals(length)) {
            publicKey = publicKey.to512();
        }
        return sm2.SM2Verify(-1, publicKey, data, signature.encode());
    }

    /**
     * SM3哈希 杂凑算法
     *
     * @param data 待杂凑数据
     * @return 杂凑值
     * @throws AFCryptoException 杂凑异常
     */
    @Override
    public byte[] SM3Hash(byte[] data) throws AFCryptoException {
        logger.info("SM3哈希 杂凑算法 data: {}", data);
        return sm3.SM3Hash(data);
    }

    /**
     * SM3哈希 杂凑算法 <br>
     * 带公钥信息和用户ID
     *
     * @param data      待杂凑数据
     * @param publicKey 公钥 可以传入256/512位公钥 实际计算使用256位公钥
     * @param userID    用户ID
     * @return 杂凑值
     * @throws AFCryptoException 杂凑异常
     */
    @Override
    public byte[] SM3HashWithPubKey(byte[] data, SM2PublicKey publicKey, byte[] userID) throws AFCryptoException {
        SM2PublicKey publicKey256 = publicKey.to256();
        return sm3.SM3HashWithPublicKey256(data, publicKey256, userID);
    }

    /**
     * SM3 HMAC  内部密钥<br>
     *
     * @param index 内部密钥索引
     * @param data  待杂凑数据
     * @return 消息验证码值
     * @throws AFCryptoException 杂凑异常
     */
    @Override
    public byte[] SM3HMac(int index, byte[] data) throws AFCryptoException {
        return sm3.SM3HMac(index, null, data);
    }

    /**
     * SM3 HMAC  外部密钥<br>
     *
     * @param key  密钥
     * @param data 待杂凑数据
     * @return 消息验证码值
     * @throws AFCryptoException 杂凑异常
     */
    @Override
    public byte[] SM3HMac(byte[] key, byte[] data) throws AFCryptoException {
        return sm3.SM3HMac(-1, key, data);
    }

    /**
     * SM4 Mac 内部密钥
     *
     * @param index 密钥索引
     * @param data  待计算数据
     * @param IV    初始向量
     * @return 消息验证码值
     */
    @Override
    public byte[] SM4Mac(int index, byte[] data, byte[] IV) throws AFCryptoException {
        logger.info("SM4Mac index: {} data: {} IV: {}", index, data, IV);
        return sm4.SM4Mac(index, data, IV);
    }

    /**
     * SM4 Mac 外部密钥
     *
     * @param key  密钥
     * @param data 待计算数据
     * @param IV   初始向量
     * @return 消息验证码值
     */
    @Override
    public byte[] SM4Mac(byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        logger.info("SM4Mac key: {} data: {} IV: {}", key, data, IV);
        return sm4.SM4Mac(key, data, IV);
    }

    /**
     * SM4 内部密钥加密
     *
     * @param mode  加密模式 ECB/CBC
     * @param index 密钥索引
     * @param data  待加密数据
     * @param IV    初始向量
     * @return 加密结果
     */
    @Override
    public byte[] SM4Encrypt(GroupMode mode, int index, byte[] data, byte[] IV) throws AFCryptoException {
        logger.info("SM4Encrypt mode: {} index: {} data: {} IV: {}", mode, index, data, IV);
        List<byte[]> singleData = splitPackage(data); //分包
        BytesBuffer buffer = new BytesBuffer();
        switch (mode) {
            case ECB:
                for (byte[] bytes : singleData) {
                    buffer.append(sm4.encrypt(index, bytes));
                }
                break;
            case CBC:
                for (byte[] bytes : singleData) {
                    buffer.append(sm4.encrypt(index, IV, bytes));
                }
                break;
            default:
                break;
        }
        return buffer.toBytes();
    }

    /**
     * SM4 内部密钥解密
     *
     * @param mode  加密模式 ECB/CBC
     * @param index 密钥索引
     * @param data  待解密数据
     * @param IV    初始向量
     * @return 解密结果
     */
    @Override
    public byte[] SM4Decrypt(GroupMode mode, int index, byte[] data, byte[] IV) throws AFCryptoException {
        logger.info("SM4Decrypt mode: {} index: {} data: {} IV: {}", mode, index, data, IV);
        List<byte[]> singleData = splitPackage(data); //分包
        BytesBuffer buffer = new BytesBuffer();
        switch (mode) {
            case ECB:
                for (byte[] bytes : singleData) {
                    buffer.append(sm4.decrypt(index, bytes));
                }
                break;
            case CBC:
                for (byte[] bytes : singleData) {
                    buffer.append(sm4.decrypt(index, bytes, IV));
                }
                break;
            default:
                break;
        }
        return cutting(buffer.toBytes());
    }

    /**
     * SM4 外部密钥加密
     *
     * @param mode 加密模式 ECB/CBC
     * @param key  密钥
     * @param data 待加密数据
     * @param IV   初始向量
     * @return 加密结果
     */
    @Override
    public byte[] SM4Encrypt(GroupMode mode, byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        logger.info("SM4Encrypt mode: {} key: {} data: {} IV: {}", mode, key, data, IV);
        List<byte[]> singleData = splitPackage(data); //分包
        BytesBuffer buffer = new BytesBuffer();
        switch (mode) {
            case ECB:
                for (byte[] bytes : singleData) {
                    buffer.append(sm4.encrypt(key, bytes));
                }
                break;
            case CBC:
                for (byte[] bytes : singleData) {
                    buffer.append(sm4.encrypt(key, IV, bytes));
                }
                break;
            default:
                break;
        }
        return buffer.toBytes();
    }

    /**
     * SM4 外部密钥解密
     *
     * @param mode 加密模式 ECB/CBC
     * @param key  密钥
     * @param data 待解密数据
     * @param IV   初始向量
     * @return 解密结果
     */
    @Override
    public byte[] SM4Decrypt(GroupMode mode, byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        logger.info("SM4Decrypt mode: {} key: {} data: {} IV: {}", mode, key, data, IV);
        List<byte[]> singleData = splitPackage(data); //分包
        BytesBuffer buffer = new BytesBuffer();
        switch (mode) {
            case ECB:
                for (byte[] bytes : singleData) {
                    buffer.append(sm4.decrypt(key, bytes));
                }
                break;
            case CBC:
                for (byte[] bytes : singleData) {
                    buffer.append(sm4.decrypt(key, bytes, IV));
                }
                break;
            default:
                break;
        }
        return cutting(buffer.toBytes());
    }

    /**
     * 获取私钥访问权限
     *
     * @param keyIndex 密钥索引
     * @param keyType  密钥类型 1:RSA; 0:SM2;
     * @param passwd   私钥访问权限口令
     * @return 0:成功; 非0:失败
     * @throws AFCryptoException 获取私钥访问权限异常
     */
    @Override
    public int getPrivateKeyAccessRight(int keyIndex, int keyType, byte[] passwd) throws AFCryptoException {
        logger.info("获取获取私钥访问权限 keyIndex:{}, keyType:{}, passwd:{}", keyIndex, keyType, passwd);
        return keyInfo.getPrivateKeyAccessRight(keyIndex, keyType, passwd);
    }

    /**
     * 获取设备内部对称密钥状态
     *
     * @return 设备内部对称密钥状态
     * @throws AFCryptoException 获取设备内部对称密钥状态异常
     */
    @Override
    public List<AFSymmetricKeyStatus> getSymmetricKeyStatus() throws AFCryptoException {
        return keyInfo.getSymmetricKeyStatus(this.agKey);
    }

    /**
     * 导入非易失对称密钥
     *
     * @param index   密钥索引
     * @param keyData 密钥数据(16进制编码)
     * @throws AFCryptoException 导入非易失对称密钥异常
     */
    @Override
    public void importKek(int index, byte[] keyData) throws AFCryptoException {
        logger.info("导入非易失对称密钥 index:{}, keyData:{}", index, keyData);
        if (index < 1 || index > ConstantNumber.MAX_KEK_COUNT) {
            throw new AFCryptoException("密钥索引输入错误");
        }

        if (keyData.length < 8 || keyData.length > 32 || keyData.length % 8 != 0) {
            throw new AFCryptoException("密钥值长度不正确，必须为8字节的倍数，最大长度32字节");
        }

        List<AFSymmetricKeyStatus> list = getSymmetricKeyStatus();
        if (list.stream().anyMatch(afs -> afs.getIndex() == index)) {
            throw new AFCryptoException("该索引已存在");
        }
        keyInfo.importKek(index, BytesOperate.hex2bytes(new String(keyData)), this.agKey);
    }

    /**
     * 销毁非易失对称密钥
     *
     * @param index 密钥索引
     * @throws AFCryptoException 销毁非易失对称密钥异常
     */
    @Override
    public void delKek(int index) throws AFCryptoException {

    }

    /**
     * 生成密钥信息
     *
     * @param keyType 密钥类型 1:对称密钥; 3:SM2密钥 4:RSA密钥;
     * @param keyBits 密钥长度 128/256/512/1024/2048/4096
     * @param count   密钥数量
     * @return 密钥信息列表
     * @throws AFCryptoException 生成密钥信息异常
     */
    @Override
    public List<AFKmsKeyInfo> generateKey(int keyType, int keyBits, int count) throws AFCryptoException {
        return null;
    }


    /**
     * 填充
     *
     * @param data 待填充数据
     * @return 填充后数据
     */
//    private static byte[] Padding(byte[] data) {
//        int paddingNumber = 16 - (data.length % 16);
//        byte[] paddingData = new byte[paddingNumber];
//        for (int i = 0; i < paddingNumber; ++i) {
//            paddingData[i] = (byte) paddingNumber;
//        }
//        byte[] outData = new byte[data.length + paddingNumber];
//        System.arraycopy(data, 0, outData, 0, data.length);
//        System.arraycopy(paddingData, 0, outData, data.length, paddingNumber);
//        return outData;
//    }
    private static byte[] Padding(byte[] data) {
        if ((data.length % 16) == 0) {
            return data;
        }
        int paddingNumber = 16 - (data.length % 16);
        byte[] paddingData = new byte[paddingNumber];
        Arrays.fill(paddingData, (byte) paddingNumber);
        byte[] outData = new byte[data.length + paddingNumber];
        System.arraycopy(data, 0, outData, 0, data.length);
        System.arraycopy(paddingData, 0, outData, data.length, paddingNumber);

        return outData;
    }


    /**
     * 去填充
     *
     * @param data 待去填充数据
     * @return 去填充后数据
     * @throws AFCryptoException 去填充异常
     */
//    private static byte[] cutting(byte[] data) throws AFCryptoException {
//        int paddingNumber = Byte.toUnsignedInt(data[data.length - 1]);
//        for (int i = 0; i < paddingNumber; ++i) {
//            if ((int) data[data.length - paddingNumber + i] != paddingNumber) {
//                throw new AFCryptoException("验证填充数据错误");
//            }
//        }
//        byte[] outData = new byte[data.length - paddingNumber];
//        System.arraycopy(data, 0, outData, 0, data.length - paddingNumber);
//        return outData;
//    }
    private static byte[] cutting(byte[] data) {
        int paddingNumber = Byte.toUnsignedInt(data[data.length - 1]);
        if (paddingNumber >= 16) paddingNumber = 0;
        for (int i = 0; i < paddingNumber; ++i) {
            if ((int) data[data.length - paddingNumber + i] != paddingNumber) {
                return null;
            }
        }
        byte[] outData = new byte[data.length - paddingNumber];
        System.arraycopy(data, 0, outData, 0, data.length - paddingNumber);
        return outData;
    }
}
