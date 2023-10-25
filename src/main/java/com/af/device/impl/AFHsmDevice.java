package com.af.device.impl;

import cn.hutool.core.util.HexUtil;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
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
import com.af.device.IAFDevice;
import com.af.device.IAFHsmDevice;
import com.af.device.cmd.AFHSMCmd;
import com.af.exception.AFCryptoException;
import com.af.netty.NettyClient;
import com.af.nettyNew.NettyClientChannels;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.impl.agreementData.AgreementData;
import com.af.struct.signAndVerify.CsrRequest;
import com.af.utils.BytesBuffer;
import com.af.utils.pkcs.AFPkcs1Operate;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
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
    //region======================================================成员与单例模式===========================================
    private static final Logger logger = LoggerFactory.getLogger(AFHsmDevice.class);
    private byte[] agKey;  //协商密钥
    @Getter
    private static NettyClient client;  //netty客户端
    private final SM3 sm3 = new SM3Impl();  //国密SM3算法
    private final AFHSMCmd cmd = new AFHSMCmd(client, agKey);

    private static final class InstanceHolder {
        static final AFHsmDevice instance = new AFHsmDevice();
    }

    public static AFHsmDevice getInstance(String host, int port, String passwd) {
        client = new NettyClientChannels.Builder(host, port, passwd, 0).build();
        return InstanceHolder.instance;
    }


    /**
     * 建造者模式
     */
    public static class Builder {

        //region//======>必须参数
        private final String host;
        private final int port;
        private final String passwd;

        //endregion
        //region//======>构造方法
        public Builder(String host, int port, String passwd) {
            //host 去除空格
            host = host.replaceAll(" ", "");
            this.host = host;
            this.port = port;
            this.passwd = passwd;
        }
        //endregion
        //region//======>可选参数

        /**
         * 是否协商密钥
         */
        private boolean isAgKey = true;
        /**
         * 连接超时时间 单位毫秒
         */
        private int connectTimeOut = 5000;

        /**
         * 响应超时时间 单位毫秒
         */
        private int responseTimeOut = 10000;

        /**
         * 重试次数
         */
        private int retryCount = 3;

        /**
         * 重试间隔 单位毫秒
         */
        private int retryInterval = 5000;

        /**
         * 缓冲区大小
         */
        private int bufferSize = 1024 * 1024;

        /**
         * 通道数量
         */
        private int channelCount = 10;
        /**
         * http端口
         */
        private static int managementPort = 443;

        //endregion
        //region//======>设置参数
        public Builder isAgKey(boolean isAgKey) {
            this.isAgKey = isAgKey;
            return this;
        }

        public Builder connectTimeOut(int connectTimeOut) {
            this.connectTimeOut = connectTimeOut;
            return this;
        }

        public Builder responseTimeOut(int responseTimeOut) {
            this.responseTimeOut = responseTimeOut;
            return this;
        }

        public Builder retryCount(int retryCount) {
            this.retryCount = retryCount;
            return this;
        }

        public Builder retryInterval(int retryInterval) {
            this.retryInterval = retryInterval;
            return this;
        }

        public Builder bufferSize(int bufferSize) {
            this.bufferSize = bufferSize;
            return this;
        }

        public Builder channelCount(int channelCount) {
            this.channelCount = channelCount;
            return this;
        }

        public Builder managementPort(int managementPort) {
            this.managementPort = managementPort;
            return this;
        }

        //endregion
        //region//======>build
        public AFHsmDevice build() {
            if (client != null) {
                return InstanceHolder.instance;
            }
            client = new NettyClientChannels.Builder(host, port, passwd, IAFDevice.generateTaskNo())
                    .timeout(connectTimeOut)
                    .responseTimeout(responseTimeOut)
                    .retryCount(retryCount)
                    .retryInterval(retryInterval)
                    .bufferSize(bufferSize)
                    .channelCount(channelCount)
                    .build();
            AFHsmDevice hsmDevice = InstanceHolder.instance;
            if (isAgKey && hsmDevice.getAgKey() == null) {
                hsmDevice.setAgKey();
            }
            return hsmDevice;
        }


        //endregion


    }

    /**
     * 协商密钥
     * @return 协商密钥后的设备
     */
    public AFHsmDevice setAgKey() {
        this.agKey = this.keyAgreement(client);
        cmd.setAgKey(agKey);
        logger.info("协商密钥成功,密钥为:{}", HexUtil.encodeHexStr(agKey));
        return this;
    }
    //endregion

    //region======================================================设备信息 随机数 私钥访问权限===============================

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
     *
     * @param length 随机数长度 字节数
     * @return 随机数
     */
    public byte[] getRandom(int length) throws AFCryptoException {
        //参数检查
        if (length <= 0 || length > ConstantNumber.MAX_RANDOM_LENGTH) {
            logger.error("随机数长度不合法,长度范围为1-4096,当前长度为:{}", length);
            throw new AFCryptoException("随机数长度不合法");
        }

        return cmd.getRandom(length);
    }

    /**
     * 获取私钥访问权限
     *
     * @param keyIndex 密钥索引
     * @param keyType  密钥类型 4:RSA; 3:SM2;
     * @param passwd   私钥访问权限口令
     */
    public void getPrivateKeyAccessRight(int keyIndex, int keyType, String passwd) throws AFCryptoException {
        logger.info("获取获取私钥访问权限 keyIndex:{}, keyType:{}, passwd:{}", keyIndex, keyType, passwd);
        if (keyIndex < 0 || keyIndex > 0xFFFF) {
            logger.error("密钥索引不合法,索引范围为0-65535,当前索引为:{}", keyIndex);
            throw new AFCryptoException("密钥索引不合法");
        }
        if (keyType != 3 && keyType != 4) {
            logger.error("密钥类型不合法,当前类型为:{}", keyType);
            throw new AFCryptoException("密钥类型不合法");
        }
        cmd.getPrivateAccess(keyIndex, keyType, passwd);
    }
    //endregion

    // region======================================================导出公钥===============================================

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
    //endregion

    //region======================================================生成密钥对======================================================

    /**
     * 生成密钥对 通用
     */
    public byte[] generateKeyPair(Algorithm algorithm, ModulusLength length) throws AFCryptoException {
        //region//======>参数检查
        //算法标识检查 只能是SM2 或者 RSA
        if (algorithm != Algorithm.SGD_SM2 && algorithm != Algorithm.SGD_RSA) {
            logger.error("生成密钥对失败,算法标识错误,algorithm(SGD_SM2|SGD_RSA):{}", algorithm);
            throw new AFCryptoException("生成密钥对失败,算法标识错误,algorithm(SGD_SM2|SGD_RSA):" + algorithm);
        }
        //模长检查 SM2只能是256 RSA只能是1024或2048
        if (algorithm == Algorithm.SGD_SM2 && length != ModulusLength.LENGTH_256) {
            logger.error("生成密钥对失败,SM2模长错误,length(256):{}", length);
            throw new AFCryptoException("生成密钥对失败,SM2模长错误,length(256):" + length);
        }
        if (algorithm == Algorithm.SGD_RSA && length != ModulusLength.LENGTH_1024 && length != ModulusLength.LENGTH_2048) {
            logger.error("生成密钥对失败,RSA模长错误,length(1024|2048):{}", length);
            throw new AFCryptoException("生成密钥对失败,RSA模长错误,length(1024|2048):" + length);
        }
        //endregion
        return cmd.generateKeyPair(algorithm, length);
    }

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
     * @param length 模长 1024 | 2048 {@link ModulusLength}
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
    //endregion

    //region======================================================会话密钥相关======================================================

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
        byte[] bytes = cmd.generateSessionKey(algorithm, keyIndex, length, null);
        BytesBuffer buffer = new BytesBuffer(bytes);
        SessionKey key = new SessionKey();
        key.setId(buffer.readInt());
        key.setLength(buffer.readInt());
        key.setKey(buffer.read(key.getLength()));
        return key;

    }

    /**
     * 导入会话密钥密文 非对称加密
     * 需要获取私钥访问权限
     *
     * @param algorithm ：对称算法标识  SGD_RSA_ENC|SGD_SM2_2
     * @param keyIndex  ：用于加密会话密钥的密钥索引
     * @param key       ：会话密钥密文
     * @return 会话密钥id
     */
    public SessionKey importSessionKey(Algorithm algorithm, int keyIndex, byte[] key) throws AFCryptoException {
        //参数检查
        if (algorithm != Algorithm.SGD_RSA_ENC && algorithm != Algorithm.SGD_SM2_2) {
            logger.error("导入会话密钥失败,算法标识错误,algorithm(SGD_RSA_ENC|SGD_SM2_2):{}", algorithm);
            throw new AFCryptoException("导入会话密钥失败,算法标识错误,algorithm(SGD_RSA_ENC|SGD_SM2_2):" + algorithm);
        }

        //导入会话密钥
        byte[] bytes = cmd.importSessionKey(algorithm, keyIndex, key);
        BytesBuffer buffer = new BytesBuffer(bytes);
        SessionKey sessionKey = new SessionKey();
        sessionKey.setId(buffer.readInt());
        return sessionKey;
    }

    /**
     * 数字信封转换
     * 需要获取私钥访问权限
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
        return cmd.convertEnvelope(algorithm, keyIndex, pubKey, data);

    }

    /**
     * 生成会话密钥（使用对称密钥）
     *
     * @param algorithm 加密算法标识 SGD_SM1_ECB|SGD_SM4_ECB
     * @param keyIndex  加密密钥索引
     * @param length    会话密钥长度 8|16|24|32
     */
    public SessionKey generateSessionKeyBySym(Algorithm algorithm, int keyIndex, int length) throws AFCryptoException {
        //参数检查
        if (algorithm != Algorithm.SGD_SM1_ECB && algorithm != Algorithm.SGD_SM4_ECB) {
            logger.error("生成会话密钥失败,算法标识错误,algorithm(SGD_SM1_ECB|SGD_SM4_ECB):{}", algorithm);
            throw new AFCryptoException("生成会话密钥失败,算法标识错误,algorithm(SGD_SM1_ECB|SGD_SM4_ECB):" + algorithm);
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
     * @param algorithm 加密算法标识 SGD_SM1_ECB|SGD_SM4_ECB
     * @param keyIndex  加密密钥索引
     * @param key       会话密钥密文
     * @return 会话密钥id 会话密钥长度
     */
    public SessionKey importSessionKeyBySym(Algorithm algorithm, int keyIndex, byte[] key) throws AFCryptoException {
        //参数检查
        if (algorithm != Algorithm.SGD_SM1_ECB && algorithm != Algorithm.SGD_SM4_ECB) {
            logger.error("导入会话密钥失败,算法标识错误,algorithm(SGD_SM1_ECB|SGD_SM4_ECB):{}", algorithm);
            throw new AFCryptoException("导入会话密钥失败,算法标识错误,algorithm(SGD_SM1_ECB|SGD_SM4_ECB):" + algorithm);
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
     * 需要获取私钥访问权限
     *
     * @param keyIndex 密钥索引
     * @param length   模长
     * @param data     协商数据
     */
    public AgreementData generateAgreementData(int keyIndex, ModulusLength length, AgreementData data) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("生成协商数据失败,密钥索引错误,keyIndex:{}", keyIndex);
            throw new AFCryptoException("生成协商数据失败,密钥索引错误,keyIndex:" + keyIndex);
        }
        if (null == data) {
            logger.error("生成协商数据失败,协商数据入参为空");
            throw new AFCryptoException("生成协商数据失败,协商数据入参为空");
        }
        if (null == data.getInitiatorId() || data.getInitiatorId().length == 0) {
            logger.error("生成协商数据失败,发起方id为空");
            throw new AFCryptoException("生成协商数据失败,发起方id为空");
        }

        byte[] bytes = cmd.generateAgreementData(keyIndex, length, data.getInitiatorId());
        BytesBuffer buffer = new BytesBuffer(bytes);
        data = new AgreementData();
        data.setPublicKey(buffer.readOneData());
        data.setTempPublicKey(buffer.readOneData());
        return data;
    }

    /**
     * 生成协商数据及密钥
     *
     * @param keyIndex 密钥索引
     * @param length   模长
     * @param data     协商数据
     * @return 协商数据
     */
    public AgreementData generateAgreementDataAndKey(int keyIndex, ModulusLength length, AgreementData data) throws AFCryptoException {
        //region //参数检查
        if (keyIndex < 0) {
            logger.error("生成协商数据失败,密钥索引错误,keyIndex:{}", keyIndex);
            throw new AFCryptoException("生成协商数据失败,密钥索引错误,keyIndex:" + keyIndex);
        }
        if (null == data) {
            logger.error("生成协商数据失败,协商数据入参为空");
            throw new AFCryptoException("生成协商数据失败,协商数据入参为空");
        }
        if (null == data.getInitiatorId() || data.getInitiatorId().length == 0) {
            logger.error("生成协商数据失败,发起方id为空");
            throw new AFCryptoException("生成协商数据失败,发起方id为空");
        }
        if (null == data.getResponderId() || data.getResponderId().length == 0) {
            logger.error("生成协商数据失败,回复方id为空");
            throw new AFCryptoException("生成协商数据失败,回复方id为空");
        }
        if (null == data.getPublicKey() || data.getPublicKey().length == 0) {
            logger.error("生成协商数据失败,公钥为空");
            throw new AFCryptoException("生成协商数据失败,公钥为空");
        }
        if (null == data.getTempPublicKey() || data.getTempPublicKey().length == 0) {
            logger.error("生成协商数据失败,临时公钥为空");
            throw new AFCryptoException("生成协商数据失败,临时公钥为空");
        }
        //endregion

//        //获取私钥访问权限
//        getPrivateKeyAccessRight(keyIndex, 3, "12345678");
        byte[] bytes = cmd.generateAgreementDataAndKey(keyIndex, length, data.getPublicKey(), data.getTempPublicKey(), data.getInitiatorId(), data.getResponderId());
        BytesBuffer buffer = new BytesBuffer(bytes);
        data = new AgreementData();
        data.setSessionId(buffer.readInt());
        data.setPublicKey(buffer.readOneData());
        data.setTempPublicKey(buffer.readOneData());
        return data;
    }

    /**
     * 生成协商密钥
     *
     * @param data AgreementData对象 协商数据入参 必须publicKey、tempPublicKey、responderId、
     * @return sessionId
     */
    public AgreementData generateAgreementKey(AgreementData data) throws AFCryptoException {
        //region //参数检查
        if (null == data) {
            logger.error("生成协商密钥失败,协商数据入参为空");
            throw new AFCryptoException("生成协商密钥失败,协商数据入参为空");
        }
        if (null == data.getPublicKey() || data.getPublicKey().length == 0) {
            logger.error("生成协商密钥失败,公钥为空");
            throw new AFCryptoException("生成协商密钥失败,公钥为空");
        }
        if (null == data.getTempPublicKey() || data.getTempPublicKey().length == 0) {
            logger.error("生成协商密钥失败,临时公钥为空");
            throw new AFCryptoException("生成协商密钥失败,临时公钥为空");
        }
        if (null == data.getResponderId() || data.getResponderId().length == 0) {
            logger.error("生成协商密钥失败,回复方id为空");
            throw new AFCryptoException("生成协商密钥失败,回复方id为空");
        }
        //endregion

        byte[] bytes = cmd.generateAgreementKey(data.getPublicKey(), data.getTempPublicKey(), data.getResponderId());
        BytesBuffer buffer = new BytesBuffer(bytes);
        data = new AgreementData();
        data.setSessionId(buffer.readInt());
        return data;
    }

    //endregion

    //region======================================================RSA======================================================

    /**
     * RSA内部密钥加密运算
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
     * RSA内部密钥解密运算 私钥解密
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 加密数据
     * @return ：返回运算结果
     */
    public byte[] rsaInternalDecrypt(int index, byte[] data) throws AFCryptoException {

        //解密
        byte[] bytes = cmd.rsaPrivateKeyOperation(index, null, Algorithm.SGD_RSA_ENC, data);
        //去填充
        return AFPkcs1Operate.pkcs1DecryptPublicKey(getRSAEncPublicKey(index).getBits(), bytes);
    }

    /**
     * RSA外部密钥加密运算 公钥加密
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
//        //获取私钥访问权限
//        getPrivateKeyAccessRight(index, 4, "12345678");
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
     * @param privateKey ：RSA私钥信息
     * @param data       : 原始数据
     * @return ：返回运算结果
     */
    public byte[] rsaExternalSign(RSAPriKey privateKey, byte[] data) throws AFCryptoException {
        //获取摘要
        byte[] hash = digestForRSASign(-1, privateKey.getBits(), data);
        //填充
        hash = AFPkcs1Operate.pkcs1EncryptionPrivate(privateKey.getBits(), hash);
        //签名 私钥加密
        return cmd.rsaPrivateKeyOperation(0, privateKey, Algorithm.SGD_RSA_SIGN, hash);
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
    //endregion

    //region=====================================================SM2计算==============================================

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
//        //获取私钥访问权限
//        getPrivateKeyAccessRight(index, 3, "12345678");
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
//        //获取私钥访问权限
//        getPrivateKeyAccessRight(index, 3, "12345678");
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
    //endregion

    //region======================================================对称加密======================================================

    /**
     * 对称加密 通用
     *
     * @param algorithm 算法标识 {@link Algorithm}
     * @param key       密钥
     * @param iv        初始向量  ECB模式下为null
     * @param plain     明文
     * @return 密文
     */
    public byte[] symmEncrypt(Algorithm algorithm, byte[] key, byte[] iv, byte[] plain) throws AFCryptoException {
        //region//======>参数检查
        if (algorithm == null) {
            logger.error("对称加密失败,算法标识不能为空");
            throw new AFCryptoException("对称加密失败,算法标识不能为空");
        }
        if (key == null || key.length == 0) {
            logger.error("对称加密失败,密钥不能为空");
            throw new AFCryptoException("对称加密失败,密钥不能为空");
        }
        //不是ECB iv不能为null
        if (!algorithm.getName().contains("ECB") && (iv == null || iv.length == 0)) {
            logger.error("对称加密失败,非ECB模式下iv不能为空");
            throw new AFCryptoException("对称加密失败,iv不能为空");
        }

        if (plain == null || plain.length == 0) {
            logger.error("对称加密失败,明文不能为空");
            throw new AFCryptoException("对称加密失败,明文不能为空");
        }
        //endregion
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(algorithm, 0, 0, key, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM4 ECB 内部密钥加密
     *
     * @param keyIndex 密钥索引
     * @param plain    原始数据
     * @return 加密数据
     */
    public byte[] sm4InternalEncryptECB(int keyIndex, byte[] plain) throws AFCryptoException {
        //region//======>参数检查
        if (keyIndex < 0) {
            logger.error("SM4 加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (plain == null || plain.length == 0) {
            logger.error("SM4 加密，加密数据不能为空");
            throw new AFCryptoException("SM4 加密，加密数据不能为空");
        }
        //endregion
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM4_ECB, 1, keyIndex, null, null, bytes.get(i));
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
        //region//======>参数检查
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
        //endregion
        //填充数据
        plain = padding(plain);
        //分包
        List<byte[]> bytes = splitPackage(plain);
        //循环加密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM4_ECB, 0, 0, key, null, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM4 ECB 密钥句柄加密
     *
     * @param keyHandle 密钥句柄
     * @param plain     原始数据
     * @return 加密数据
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
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM4_ECB, 2, keyHandle, null, null, bytes.get(i));
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
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM4_CBC, 1, keyIndex, null, iv, bytes.get(i));
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
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM4_CBC, 0, 0, key, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM4 CBC 密钥句柄加密
     *
     * @param keyHandle 密钥句柄
     * @param iv        初始向量 16字节
     * @param plain     明文
     * @return 密文
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
            byte[] encrypt = cmd.symEncrypt(Algorithm.SGD_SM4_CBC, 2, keyHandle, null, iv, bytes.get(i));
            bytes.set(i, encrypt);
        }
        return mergePackage(bytes);
    }

    /**
     * SM1 内部加密 ECB
     *
     * @param keyIndex 密钥索引
     * @param plain    明文
     * @return 密文
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
     *
     * @param key   密钥
     * @param plain 明文
     * @return 密文
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
     *
     * @param keyHandle 密钥句柄
     * @param plain     明文
     * @return 密文
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
     *
     * @param keyIndex 密钥索引
     * @param iv       初始向量
     * @param plain    明文
     * @return 密文
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
     *
     * @param key   密钥
     * @param iv    初始向量
     * @param plain 明文
     * @return 密文
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
     *
     * @param keyHandle 密钥句柄
     * @param iv        初始向量
     * @param plain     明文
     * @return 密文
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
    //endregion

    //region======================================================对称解密======================================================

    /**
     * 对称解密 通用
     *
     * @param algorithm 算法标识 {@link Algorithm}
     * @param key       密钥
     * @param iv        初始向量  ECB模式下为null
     * @param cipher    密文
     * @return 明文
     */
    public byte[] symmDecrypt(Algorithm algorithm, byte[] key, byte[] iv, byte[] cipher) throws AFCryptoException {
        //region//======>参数检查
        if (algorithm == null) {
            logger.error("对称解密失败,算法标识不能为空");
            throw new AFCryptoException("对称解密失败,算法标识不能为空");
        }
        if (key == null || key.length == 0) {
            logger.error("对称解密失败,密钥不能为空");
            throw new AFCryptoException("对称解密失败,密钥不能为空");
        }

        if (cipher == null || cipher.length == 0) {
            logger.error("对称解密失败,密文不能为空");
            throw new AFCryptoException("对称解密失败,密文不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
        //循环解密
        for (int i = 0; i < bytes.size(); i++) {
            byte[] decrypt = cmd.symDecrypt(algorithm, 0, 0, key, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合并数据 并去填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 内部密钥 解密 ECB
     *
     * @param keyIndex 密钥索引
     * @param cipher   密文
     * @return 明文
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
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM4_ECB, 1, keyIndex, null, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));

    }

    /**
     * SM4 外部密钥 解密 ECB
     *
     * @param key    密钥
     * @param cipher 密文
     * @return 明文
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
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM4_ECB, 0, -1, key, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 密钥句柄 解密 ECB
     *
     * @param keyHandle 密钥句柄
     * @param cipher    密文
     * @return 明文
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
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM4_ECB, 2, keyHandle, null, null, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 内部密钥 解密 CBC
     *
     * @param keyIndex 密钥索引
     * @param iv       初始向量
     * @param cipher   密文
     * @return 明文
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
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM4_CBC, 1, keyIndex, null, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 外部密钥 解密 CBC
     *
     * @param key    密钥
     * @param iv     初始向量
     * @param cipher 密文
     * @return 明文
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
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM4_CBC, 0, -1, key, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM4 密钥句柄 解密 CBC
     *
     * @param keyHandle 密钥句柄
     * @param iv        初始向量
     * @param cipher    密文
     * @return 明文
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
            byte[] decrypt = cmd.symDecrypt(Algorithm.SGD_SM4_CBC, 2, keyHandle, null, iv, bytes.get(i));
            bytes.set(i, decrypt);
        }
        //合包 去除填充
        return cutting(mergePackage(bytes));
    }

    /**
     * SM1 内部解密 ECB
     *
     * @param keyIndex 密钥索引
     * @param cipher   密文
     * @return 明文
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
     *
     * @param key    密钥
     * @param cipher 密文
     * @return 明文
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
     *
     * @param keyHandle 密钥句柄
     * @param cipher    密文
     * @return 明文
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
     *
     * @param keyIndex 密钥索引
     * @param iv       初始向量
     * @param cipher   明文
     * @return 密文
     */
    public byte[] sm1InternalDecryptCBC(int keyIndex, byte[] iv, byte[] cipher) throws AFCryptoException {
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
        if (cipher == null || cipher.length == 0) {
            logger.error("SM1 解密，加密数据不能为空");
            throw new AFCryptoException("SM1 解密，加密数据不能为空");
        }
        //分包
        List<byte[]> bytes = splitPackage(cipher);
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
     *
     * @param key    密钥
     * @param iv     初始向量
     * @param cipher 密文
     * @return 明文
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
     *
     * @param keyHandle 密钥句柄
     * @param iv        初始向量
     * @param cipher    密文
     * @return 明文
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
    //endregion

    //region======================================================批量加密======================================================

    /**
     * 批量对称加密 通用
     */
    public List<byte[]> batchSymmEncrypt(Algorithm algorithm, byte[] key, byte[] iv, List<byte[]> plainList) throws AFCryptoException {
        //region//======>参数检查
        if (algorithm == null) {
            logger.error("对称批量加密失败,算法标识不能为空");
            throw new AFCryptoException("对称批量加密失败,算法标识不能为空");
        }
        if (key == null || key.length == 0) {
            logger.error("对称批量加密失败,密钥不能为空");
            throw new AFCryptoException("对称批量加密失败,密钥不能为空");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("对称批量加密失败,加密数据列表不能为空");
            throw new AFCryptoException("对称批量加密失败,加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("对称批量加密失败,加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("对称批量加密失败,加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(algorithm, 0, 0, key, iv, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }


    /**
     * SM4 内部批量加密 ECB
     *
     * @param keyIndex  密钥索引
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm4InternalBatchEncryptECB(int keyIndex, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 批量加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 批量加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM4 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM4 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());

        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }

        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM4_ECB, 1, keyIndex, null, null, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4外部批量加密 ECB
     *
     * @param keyIndex  密钥索引
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm4ExternalBatchEncryptECB(byte[] keyIndex, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (keyIndex == null || keyIndex.length == 0) {
            logger.error("SM4 批量加密，索引不能为空");
            throw new AFCryptoException("SM4 批量加密，索引不能为空");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM4 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM4 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());

        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM4_ECB, 0, 0, keyIndex, null, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4 密钥句柄批量加密 ECB
     *
     * @param keyHandle 密钥句柄
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm4HandleBatchEncryptECB(int keyHandle, List<byte[]> plainList) throws AFCryptoException {
        //参数检查

        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM4 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM4 批量加密，加密数据不能为空");
        }

        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());

        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);

        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM4_ECB, 2, keyHandle, null, null, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4 内部批量加密 CBC
     *
     * @param keyIndex  密钥索引
     * @param iv        初始向量
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm4InternalBatchEncryptCBC(int keyIndex, byte[] iv, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 批量加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 批量加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM4 批量加密，iv不能为空，且长度必须为16");
            throw new AFCryptoException("SM4 批量加密，iv不能为空，且长度必须为16");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM4 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM4 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM4_CBC, 1, keyIndex, null, iv, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4 外部批量加密 CBC
     *
     * @param key       密钥
     * @param iv        初始向量
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm4ExternalBatchEncryptCBC(byte[] key, byte[] iv, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (key == null || key.length != 16) {
            logger.error("SM4 批量加密，key不能为空，且长度必须为16");
            throw new AFCryptoException("SM4 批量加密，key不能为空，且长度必须为16");
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM4 批量加密，iv不能为空，且长度必须为16");
            throw new AFCryptoException("SM4 批量加密，iv不能为空，且长度必须为16");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM4 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM4 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM4_CBC, 0, 0, key, iv, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4 密钥句柄批量加密 CBC
     *
     * @param keyHandle 密钥句柄
     * @param iv        初始向量
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm4HandleBatchEncryptCBC(int keyHandle, byte[] iv, List<byte[]> plainList) throws AFCryptoException {

        //参数检查
        if (iv == null || iv.length != 16) {
            logger.error("SM4 批量加密，iv不能为空，且长度必须为16");
            throw new AFCryptoException("SM4 批量加密，iv不能为空，且长度必须为16");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM4 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM4 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM4_CBC, 2, keyHandle, null, iv, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM4 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM4 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 内部批量加密 ECB
     *
     * @param keyIndex  密钥索引
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm1InternalBatchEncryptECB(int keyIndex, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 批量加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM1 批量加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM1 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM1 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM1_ECB, 1, keyIndex, null, null, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM1 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM1 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 外部批量加密 ECB
     *
     * @param key       密钥
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm1ExternalBatchEncryptECB(byte[] key, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (key == null || key.length != 16) {
            logger.error("SM1 批量加密，密钥不能为空，且长度必须为16");
            throw new AFCryptoException("SM1 批量加密，密钥不能为空，且长度必须为16");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM1 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM1 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);

        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM1_ECB, 0, 0, key, null, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM1 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM1 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 密钥句柄批量加密 ECB
     *
     * @param keyHandle 密钥句柄
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm1HandleBatchEncryptECB(int keyHandle, List<byte[]> plainList) throws AFCryptoException {
        //参数检查

        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }

        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM1_ECB, 2, keyHandle, null, null, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM1 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM1 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 内部密钥批量加密 CBC
     *
     * @param keyIndex  密钥索引
     * @param iv        初始向量
     * @param plainList 明文列表
     */
    public List<byte[]> sm1InternalBatchEncryptCBC(int keyIndex, byte[] iv, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 批量加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM1 批量加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM1 批量加密，iv不能为空，且长度必须为16");
            throw new AFCryptoException("SM1 批量加密，iv不能为空，且长度必须为16");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM1 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM1 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM1_CBC, 1, keyIndex, null, iv, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM1 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM1 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 外部密钥批量加密 CBC
     *
     * @param key       密钥
     * @param iv        初始向量
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm1ExternalBatchEncryptCBC(byte[] key, byte[] iv, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (null == key || key.length == 0) {
            logger.error("SM1 批量加密，外部密钥不能为空");
            throw new AFCryptoException("SM1 批量加密，外部密钥不能为空");
        }
        if (null == iv || iv.length == 0) {
            logger.error("SM1 批量加密，iv不能为空");
            throw new AFCryptoException("SM1 批量加密，iv不能为空");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM1 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM1 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM1_CBC, 0, 0, key, iv, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM1 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM1 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 密钥句柄批量加密 CBC
     *
     * @param keyHandle 密钥句柄
     * @param iv        初始向量
     * @param plainList 明文列表
     * @return 密文列表
     */
    public List<byte[]> sm1HandleBatchEncryptCBC(int keyHandle, byte[] iv, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (null == iv || iv.length == 0) {
            logger.error("SM1 批量加密，iv不能为空");
            throw new AFCryptoException("SM1 批量加密，iv不能为空");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM1 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM1 批量加密，加密数据不能为空");
        }
        //记录明文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream().map(AFHsmDevice::padding).collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM1_CBC, 2, keyHandle, null, iv, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != plainList.size()) {
            logger.error("SM1 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", plainList.size(), count);
            throw new AFCryptoException("SM1 批量加密，加密数据个数不匹配，期望个数：" + plainList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        List<byte[]> collect = IntStream.range(0, count).mapToObj(i -> buf.readOneData()).collect(Collectors.toList());
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }
    //endregion

    //region======================================================批量解密======================================================

    /**
     * 批量对称解密 通用
     */
    public List<byte[]> batchSymmDecrypt(Algorithm algorithm, byte[] key, byte[] iv, List<byte[]> plainList) throws AFCryptoException {
        //region//======>参数检查
        if (algorithm == null) {
            logger.error("批量解密，算法不能为空");
            throw new AFCryptoException("批量解密，算法不能为空");
        }
        if (plainList == null || plainList.isEmpty()) {
            logger.error("批量解密，解密数据不能为空");
            throw new AFCryptoException("批量解密，解密数据不能为空");
        }
        //endregion
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < plainList.size(); i++) {
            if (plainList.get(i) == null || plainList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        plainList = plainList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = plainList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(algorithm, 0, 0, key, iv, plainList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        //循环读取放入list
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }


    /**
     * SM4 内部批量解密 ECB
     *
     * @param keyIndex   密钥索引
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm4InternalBatchDecryptECB(int keyIndex, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 批量解密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 批量解密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }

        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());

        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM4_ECB, 1, keyIndex, null, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4 外部批量解密 ECB
     *
     * @param key        密钥
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm4ExternalBatchDecryptECB(byte[] key, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM4 批量解密，密钥不能为空");
            throw new AFCryptoException("SM4 批量解密，密钥不能为空");
        }

        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM4_ECB, 0, 0, key, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;

    }

    /**
     * SM4 密钥句柄批量解密 ECB
     *
     * @param keyHandle  密钥句柄
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm4HandleBatchDecryptECB(int keyHandle, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM4_ECB, 2, keyHandle, null, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4 内部批量解密 CBC
     *
     * @param keyIndex   密钥索引
     * @param iv         初始向量
     * @param cipherList 密文列表
     */
    public List<byte[]> sm4InternalBatchDecryptCBC(int keyIndex, byte[] iv, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 批量解密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM4 批量解密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM4 批量解密，iv长度必须为16");
            throw new AFCryptoException("SM4 批量解密，iv长度必须为16");
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM4_CBC, 1, keyIndex, null, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4 外部密钥批量解密 CBC
     *
     * @param key        密钥
     * @param iv         初始向量
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm4ExternalBatchDecryptCBC(byte[] key, byte[] iv, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (key == null || key.length != 16) {
            logger.error("SM4 批量解密，密钥长度必须为16");
            throw new AFCryptoException("SM4 批量解密，密钥长度必须为16");
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM4 批量解密，iv长度必须为16");
            throw new AFCryptoException("SM4 批量解密，iv长度必须为16");
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM4_CBC, 0, 0, key, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM4 密钥句柄批量解密 CBC
     *
     * @param keyHandle  密钥句柄
     * @param iv         初始向量
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm4HandleBatchDecryptCBC(int keyHandle, byte[] iv, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查

        if (iv == null || iv.length != 16) {
            logger.error("SM4 批量解密，iv长度必须为16");
            throw new AFCryptoException("SM4 批量解密，iv长度必须为16");
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM4_CBC, 2, keyHandle, null, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 内部密钥批量解密 ECB
     *
     * @param keyIndex   密钥索引
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm1InternalBatchDecryptECB(int keyIndex, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 批量解密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM1 批量解密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM1 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM1 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM1_ECB, 1, keyIndex, null, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM1 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM1 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 外部密钥批量解密 ECB
     *
     * @param key        密钥
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm1ExternalBatchDecryptECB(byte[] key, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (key == null || key.length != 16) {
            logger.error("SM1 批量解密，密钥长度必须为16");
            throw new AFCryptoException("SM1 批量解密，密钥长度必须为16");
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM1 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM1 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM1_ECB, 0, 0, key, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM1 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM1 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 密钥句柄批量解密 ECB
     *
     * @param keyHandle  密钥句柄
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm1HandleBatchDecryptECB(int keyHandle, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查

        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM1 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM1 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM1_ECB, 2, keyHandle, null, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM1 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM1 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 内部密钥批量解密 CBC
     *
     * @param keyIndex   密钥索引
     * @param iv         向量
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm1InternalBatchDecryptCBC(int keyIndex, byte[] iv, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 批量解密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM1 批量解密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM1 批量解密，iv长度必须为16");
            throw new AFCryptoException("SM1 批量解密，iv长度必须为16");
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM1 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM1 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM1_CBC, 1, keyIndex, null, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM1 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM1 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 外部密钥批量解密 CBC
     *
     * @param key        密钥
     * @param iv         向量
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm1ExternalBatchDecryptCBC(byte[] key, byte[] iv, List<byte[]> cipherList) throws AFCryptoException {

        //参数检查
        if (key == null || key.length != 16) {
            logger.error("SM1 批量解密，密钥长度必须为16");
            throw new AFCryptoException("SM1 批量解密，密钥长度必须为16");
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM1 批量解密，iv长度必须为16");
            throw new AFCryptoException("SM1 批量解密，iv长度必须为16");
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM1 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM1 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM1_CBC, 0, 0, key, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM1 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM1 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }

    /**
     * SM1 密钥句柄批量解密 CBC
     *
     * @param keyHandle  密钥句柄
     * @param iv         向量
     * @param cipherList 密文列表
     * @return 明文列表
     */
    public List<byte[]> sm1HandleBatchDecryptCBC(int keyHandle, byte[] iv, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查

        if (iv == null || iv.length != 16) {
            logger.error("SM1 批量解密，iv长度必须为16");
            throw new AFCryptoException("SM1 批量解密，iv长度必须为16");
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM1 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM1 批量解密，解密数据不能为空");
        }
        //记录密文列表空值索引 并去除空值
        List<Integer> nullIndex = new ArrayList<>();
        for (int i = 0; i < cipherList.size(); i++) {
            if (cipherList.get(i) == null || cipherList.get(i).length == 0) {
                nullIndex.add(i);
            }
        }
        cipherList = cipherList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        //list 总长度<2M
        int totalLength = cipherList.stream().mapToInt(bytes -> bytes.length).sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SM1_CBC, 2, keyHandle, null, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM1 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM1 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        List<byte[]> collect = getCollect(buf, count);
        //空值填充  原值后移
        for (Integer index : nullIndex) {
            collect.add(index, null);
        }
        return collect;
    }
    //endregion

    //region======================================================MAC 计算======================================================


    /**
     * Mac 通用
     *
     * @param algorithm 算法 必须是CBC模式 {@link Algorithm}
     * @param key       密钥
     * @param iv        向量
     * @param data      计算数据
     * @return MAC     消息认证码
     */
    public byte[] mac(Algorithm algorithm, byte[] key, byte[] iv, byte[] data) throws AFCryptoException {
        //参数检查
        if (algorithm == null) {
            logger.error("MAC 计算，算法不能为空");
            throw new AFCryptoException("MAC 计算，算法不能为空");
        }
        if (key == null || key.length == 0) {
            logger.error("MAC 计算，密钥不能为空");
            throw new AFCryptoException("MAC 计算，密钥不能为空");
        }
        if (iv == null || iv.length == 0) {
            logger.error("MAC 计算，iv不能为空");
            throw new AFCryptoException("MAC 计算，iv不能为空");
        }

        if (data == null || data.length == 0) {
            logger.error("MAC 计算，计算数据不能为空");
            throw new AFCryptoException("MAC 计算，计算数据不能为空");
        }
        data = padding(data);
        return cmd.mac(algorithm, 0, 0, key, iv, data);
    }

    /**
     * SM4 计算MAC 内部密钥
     *
     * @param keyIndex 密钥索引
     * @param iv       向量
     * @param data     计算数据
     * @return MAC
     */
    public byte[] sm4InternalMac(int keyIndex, byte[] iv, byte[] data) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM4 计算MAC，密钥索引必须大于等于0");
            throw new AFCryptoException("SM4 计算MAC，密钥索引必须大于等于0");
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM4 计算MAC，iv长度必须为16");
            throw new AFCryptoException("SM4 计算MAC，iv长度必须为16");
        }
        if (data == null || data.length == 0) {
            logger.error("SM4 计算MAC，计算数据不能为空");
            throw new AFCryptoException("SM4 计算MAC，计算数据不能为空");
        }
        data = padding(data);
        return cmd.mac(Algorithm.SGD_SM4_CBC, 1, keyIndex, null, iv, data);
    }

    /**
     * SM4 计算MAC 外部密钥
     *
     * @param key  密钥
     * @param iv   向量
     * @param data 计算数据
     * @return MAC
     */
    public byte[] sm4ExternalMac(byte[] key, byte[] iv, byte[] data) throws AFCryptoException {
        //参数检查
        if (key == null || key.length != 16) {
            logger.error("SM4 计算MAC，密钥长度必须为16");
            throw new AFCryptoException("SM4 计算MAC，密钥长度必须为16");
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM4 计算MAC，iv长度必须为16");
            throw new AFCryptoException("SM4 计算MAC，iv长度必须为16");
        }
        if (data == null || data.length == 0) {
            logger.error("SM4 计算MAC，计算数据不能为空");
            throw new AFCryptoException("SM4 计算MAC，计算数据不能为空");
        }
        data = padding(data);
        return cmd.mac(Algorithm.SGD_SM4_CBC, 0, 0, key, iv, data);
    }

    /**
     * SM4 计算MAC 密钥句柄
     *
     * @param keyHandle 密钥句柄
     * @param iv        向量
     * @param data      计算数据
     * @return MAC
     */
    public byte[] sm4HandleMac(int keyHandle, byte[] iv, byte[] data) throws AFCryptoException {
        //参数检查

        if (iv == null || iv.length != 16) {
            logger.error("SM4 计算MAC，iv长度必须为16");
            throw new AFCryptoException("SM4 计算MAC，iv长度必须为16");
        }
        if (data == null || data.length == 0) {
            logger.error("SM4 计算MAC，计算数据不能为空");
            throw new AFCryptoException("SM4 计算MAC，计算数据不能为空");
        }
        data = padding(data);
        return cmd.mac(Algorithm.SGD_SM4_CBC, 2, keyHandle, null, iv, data);
    }

    /**
     * SM1 计算MAC 内部密钥
     *
     * @param keyIndex 密钥索引
     * @param iv       向量
     * @param data     计算数据
     * @return MAC
     */
    public byte[] sm1InternalMac(int keyIndex, byte[] iv, byte[] data) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 计算MAC，密钥索引必须大于等于0");
            throw new AFCryptoException("SM1 计算MAC，密钥索引必须大于等于0");
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM1 计算MAC，iv长度必须为16");
            throw new AFCryptoException("SM1 计算MAC，iv长度必须为16");
        }
        if (data == null || data.length == 0) {
            logger.error("SM1 计算MAC，计算数据不能为空");
            throw new AFCryptoException("SM1 计算MAC，计算数据不能为空");
        }
        data = padding(data);
        return cmd.mac(Algorithm.SGD_SM1_CBC, 1, keyIndex, null, iv, data);
    }

    /**
     * SM1 计算MAC 外部密钥
     *
     * @param key  密钥
     * @param iv   向量
     * @param data 计算数据
     * @return MAC
     */
    public byte[] sm1ExternalMac(byte[] key, byte[] iv, byte[] data) throws AFCryptoException {
        //参数检查
        if (key == null || key.length != 16) {
            logger.error("SM1 计算MAC，密钥长度必须为16");
            throw new AFCryptoException("SM1 计算MAC，密钥长度必须为16");
        }
        if (iv == null || iv.length != 16) {
            logger.error("SM1 计算MAC，iv长度必须为16");
            throw new AFCryptoException("SM1 计算MAC，iv长度必须为16");
        }
        if (data == null || data.length == 0) {
            logger.error("SM1 计算MAC，计算数据不能为空");
            throw new AFCryptoException("SM1 计算MAC，计算数据不能为空");
        }
        data = padding(data);
        return cmd.mac(Algorithm.SGD_SM1_CBC, 0, 0, key, iv, data);
    }

    /**
     * SM1 计算MAC 密钥句柄
     *
     * @param keyHandle 密钥句柄
     * @param iv        向量
     * @param data      计算数据
     * @return MAC
     */
    public byte[] sm1HandleMac(int keyHandle, byte[] iv, byte[] data) throws AFCryptoException {
        //参数检查

        if (iv == null || iv.length != 16) {
            logger.error("SM1 计算MAC，iv长度必须为16");
            throw new AFCryptoException("SM1 计算MAC，iv长度必须为16");
        }
        if (data == null || data.length == 0) {
            logger.error("SM1 计算MAC，计算数据不能为空");
            throw new AFCryptoException("SM1 计算MAC，计算数据不能为空");
        }
        data = padding(data);
        return cmd.mac(Algorithm.SGD_SM1_CBC, 2, keyHandle, null, iv, data);
    }

    /**
     * SM3-HMAC
     *
     * @param key  密钥
     * @param data 计算数据
     */
    public byte[] sm3Hmac(byte[] key, byte[] data) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM3-HMAC，密钥不能为空");
            throw new AFCryptoException("SM3-HMAC，密钥不能为空");
        }
        if (data == null || data.length == 0) {
            logger.error("SM3-HMAC，计算数据不能为空");
            throw new AFCryptoException("SM3-HMAC，计算数据不能为空");
        }
        return cmd.sm3Hmac(key, data);
    }
    //endregion

    //region======================================================Hash计算======================================================

    /**
     * Hash init
     */
    public void sm3HashInit() throws AFCryptoException {
        cmd.hashInit(Algorithm.SGD_SM3, null, null);
    }

    /**
     * Hash init 带公钥
     *
     * @param publicKey 公钥
     * @param userId    用户ID
     */
    public void sm3HashInitWithPubKey(SM2PublicKey publicKey, byte[] userId) throws AFCryptoException {
        //参数检查
        if (publicKey == null) {
            logger.error("SM3 Hash init(带公钥)，公钥不能为空");
            throw new AFCryptoException("SM3 Hash init(带公钥)，公钥不能为空");
        }
        if (userId == null || userId.length == 0) {
            logger.error("SM3 Hash init(带公钥)，用户ID不能为空");
            throw new AFCryptoException("SM3 Hash init(带公钥)，用户ID不能为空");
        }
        cmd.hashInit(Algorithm.SGD_SM3, publicKey.encode(), userId);
    }

    /**
     * Hash update
     *
     * @param data 计算数据
     */
    public void sm3HashUpdate(byte[] data) throws AFCryptoException {
        //参数检查
        if (data == null || data.length == 0) {
            logger.error("SM3 Hash update，计算数据不能为空");
            throw new AFCryptoException("SM3 Hash update，计算数据不能为空");
        }
        cmd.hashUpdate(data);
    }

    /**
     * Hash doFinal
     *
     * @return Hash
     */
    public byte[] sm3HashFinal() throws AFCryptoException {
        return cmd.hashFinal();
    }


    /**
     * SM3 Hash
     *
     * @param data 计算数据
     * @return Hash
     */
    public byte[] sm3Hash(byte[] data) throws AFCryptoException {
        //region//======>参数检查
        if (data == null || data.length == 0) {
            logger.error("SM3 Hash，计算数据不能为空");
            throw new AFCryptoException("SM3 Hash，计算数据不能为空");
        }
        //endregion
        return cmd.hash(null, null, data);
    }

    /**
     * SM3 Hash 带公钥
     *
     * @param publicKey 公钥
     * @param userId    用户ID
     * @param data      计算数据
     * @return Hash
     */
    public byte[] sm3HashWithPubKey(SM2PublicKey publicKey, byte[] userId, byte[] data) throws AFCryptoException {
        //region//======>参数检查
        if (publicKey == null) {
            logger.error("SM3 Hash(带公钥)，公钥不能为空");
            throw new AFCryptoException("SM3 Hash(带公钥)，公钥不能为空");
        }
        if (userId == null || userId.length == 0) {
            logger.error("SM3 Hash(带公钥)，用户ID不能为空");
            throw new AFCryptoException("SM3 Hash(带公钥)，用户ID不能为空");
        }
        if (data == null || data.length == 0) {
            logger.error("SM3 Hash(带公钥)，计算数据不能为空");
            throw new AFCryptoException("SM3 Hash(带公钥)，计算数据不能为空");
        }
        //endregion
        return cmd.hash(publicKey.encode(), userId, data);
    }
    //endregion

    //region======================================================文件操作======================================================

    /**
     * 创建文件
     *
     * @param fileName 文件名
     * @param fileSize 文件大小
     */
    public void createFile(String fileName, int fileSize) throws AFCryptoException {
        //参数检查
        if (fileName == null || fileName.isEmpty()) {
            logger.error("创建文件，文件名不能为空");
            throw new AFCryptoException("创建文件，文件名不能为空");
        }
        if (fileSize <= 0) {
            logger.error("创建文件，文件大小必须大于0");
            throw new AFCryptoException("创建文件，文件大小必须大于0");
        }
        cmd.createFile(fileName, fileSize);
    }

    /**
     * 读取文件
     *
     * @param fileName 文件名
     * @param offset   偏移量
     * @param length   读取长度
     * @return 读取数据
     */
    public byte[] readFile(String fileName, int offset, int length) throws AFCryptoException {
        //参数检查
        if (fileName == null || fileName.isEmpty()) {
            logger.error("读取文件，文件名不能为空");
            throw new AFCryptoException("读取文件，文件名不能为空");
        }
        if (offset < 0) {
            logger.error("读取文件，偏移量必须大于等于0");
            throw new AFCryptoException("读取文件，偏移量必须大于等于0");
        }
        if (length <= 0) {
            logger.error("读取文件，读取长度必须大于0");
            throw new AFCryptoException("读取文件，读取长度必须大于0");
        }
        return cmd.readFile(fileName, offset, length);
    }

    /**
     * 写入文件
     *
     * @param fileName 文件名
     * @param offset   偏移量
     * @param data     写入数据
     */
    public void writeFile(String fileName, int offset, byte[] data) throws AFCryptoException {
        //参数检查
        if (fileName == null || fileName.isEmpty()) {
            logger.error("写入文件，文件名不能为空");
            throw new AFCryptoException("写入文件，文件名不能为空");
        }
        if (offset < 0) {
            logger.error("写入文件，偏移量必须大于等于0");
            throw new AFCryptoException("写入文件，偏移量必须大于等于0");
        }
        if (data == null || data.length == 0) {
            logger.error("写入文件，写入数据不能为空");
            throw new AFCryptoException("写入文件，写入数据不能为空");
        }
        cmd.writeFile(fileName, offset, data);
    }

    /**
     * 删除文件
     *
     * @param fileName 文件名
     */
    public void deleteFile(String fileName) throws AFCryptoException {
        //参数检查
        if (fileName == null || fileName.isEmpty()) {
            logger.error("删除文件，文件名不能为空");
            throw new AFCryptoException("删除文件，文件名不能为空");
        }
        cmd.deleteFile(fileName);
    }
    //endregion

    //region//==================================P10 Http 证书请求与导入=================================================

    /**
     * 根据密钥索引产生证书请求
     *
     * @param keyIndex   密钥索引
     * @param csrRequest 证书请求信息 {@link CsrRequest}
     * @return CSR文件 Base64编码
     */
    public String getCSRByIndex(int keyIndex, CsrRequest csrRequest) throws AFCryptoException {
        // 获取服务器地址和端口
        String ip = "";
        int port = AFHsmDevice.Builder.managementPort;
        if (client instanceof NettyClientChannels) {
            ip = ((NettyClientChannels) client).getNettyChannelPool().getHost();
        }
        //设置请求头
        HashMap<String, String> header = new HashMap<>();
        header.put("Content-Type", "application/json");
        //设置请求参数
        JSONObject params = new JSONObject();
        params.set("keyIndex", keyIndex);
        params.set("dn", csrRequest.toDn());
        String url = "https://" + ip + ":" + port + "/mngapi/asymm/generate";
        //发送请求
        int retry = 3;
        while (true) {
            String body = HttpUtil.createPost(url)
                    .setConnectionTimeout(5 * 1000)
                    .addHeaders(header)
                    .body(params.toString())
                    .execute()
                    .body();
            JSONObject jsonObject = null;
            try {
                jsonObject = JSONUtil.parseObj(body);
            } catch (Exception e) {
                throw new AFCryptoException("HSM-Dev Error: " + "解析服务器响应失败");
            }
            logger.info("HSM-Dev Response: " + jsonObject.toStringPretty());
            int status = jsonObject.getInt("status");
            if (status == 200) {
                return jsonObject.getJSONObject("result").getStr("csr");
            } else {
                if (retry-- > 0) {
                    continue;
                }
                throw new AFCryptoException("HSM-Dev Error: " + jsonObject.getStr("message"));
            }
        }


    }

    /**
     * 根据密钥索引导入证书
     *
     * @param keyIndex  密钥索引
     * @param signCert  签名证书
     * @param encCert   加密证书
     * @param encPriKey 加密密钥
     */
    public void importCertByIndex(int keyIndex, String signCert, String encCert, String encPriKey) throws AFCryptoException {
        // 获取服务器地址和端口
        String ip = "";
        int port = AFHsmDevice.Builder.managementPort;
        if (client instanceof NettyClientChannels) {
            ip = ((NettyClientChannels) client).getNettyChannelPool().getHost();
        }

        HashMap<String, String> header = new HashMap<>();
        header.put("Content-Type", "application/json");

        JSONObject params = new JSONObject();
        params.set("keyIndex", keyIndex);
        params.set("signCert", signCert);
        params.set("encCert", encCert);
        params.set("encPriKey", encPriKey);
        String url = "https://" + ip + ":" + port + "/mngapi/asymm/importCert";
        int retry = 3;
        while (true) {
            String body = HttpUtil.createPost(url)
                    .setConnectionTimeout(5 * 1000)
                    .addHeaders(header)
                    .body(params.toString())
                    .execute()
                    .body();
            JSONObject jsonObject = null;
            try {
                jsonObject = JSONUtil.parseObj(body);
            } catch (Exception e) {
                throw new AFCryptoException("HSM-Dev Error: " + "解析服务器响应失败");
            }
            logger.info("HSM-Dev Response: " + jsonObject.toStringPretty());

            int status = jsonObject.getInt("status");
            if (status == 200) {
                return;
            } else {
                if (retry-- > 0) {
                    continue;
                }
                throw new AFCryptoException("HSM-Dev Error: " + jsonObject.getStr("message"));
            }
        }
    }

    /**
     * 根据密钥索引获取证书
     *
     * @param keyIndex 密钥索引
     * @return Map<String, String> 证书Map key:证书类型( encCert|signCert ) value:如果存在则为证书内容，否则为null
     */
    public Map<String, String> getCertByIndex(int keyIndex) throws AFCryptoException {
        // 获取服务器地址和端口
        String ip = "";
        int port = AFHsmDevice.Builder.managementPort;
        if (client instanceof NettyClientChannels) {
            ip = ((NettyClientChannels) client).getNettyChannelPool().getHost();
        }
        // 设置请求头
        HashMap<String, String> header = new HashMap<>();
        header.put("Content-Type", "application/json");
        // 设置请求参数
        JSONObject params = new JSONObject();
        params.set("keyIndex", keyIndex);
        String url = "https://" + ip + ":" + port + "/mngapi/asymm/getCert";
        // 最大重试次数
        int retry = 3;
        // 发送请求
        while (true) {
            String body = HttpUtil.createPost(url)
                    .setConnectionTimeout(5 * 1000)
                    .addHeaders(header)
                    .body(params.toString())
                    .execute()
                    .body();
            JSONObject jsonObject = null;
            try {
                jsonObject = JSONUtil.parseObj(body);
            } catch (Exception e) {
                throw new AFCryptoException("HSM-Dev Error: " + "解析服务器响应失败");
            }
            logger.info("HSM-Dev Response: " + jsonObject.toStringPretty());

            int status = jsonObject.getInt("status");
            if (status == 200) {
                String encCert = jsonObject.getJSONObject("result").getStr("encCert");
                String signCert = jsonObject.getJSONObject("result").getStr("signCert");
                Map<String, String> map = new HashMap<>();
                map.put("encCert", encCert);
                map.put("signCert", signCert);
                return map;
            } else {
                if (retry-- > 0) {
                    continue;
                }
                throw new AFCryptoException("HSM-Dev Error: " + jsonObject.getStr("message"));
            }
        }
    }


    /**
     * 删除密钥
     *
     * @param keyIndex 密钥索引
     */
    public void deleteKey(int keyIndex) throws AFCryptoException {

        // 获取服务器地址和端口
        String ip = "";
        int port = AFHsmDevice.Builder.managementPort;
        if (client instanceof NettyClientChannels) {
            ip = ((NettyClientChannels) client).getNettyChannelPool().getHost();
        }
        // 设置请求头
        HashMap<String, String> header = new HashMap<>();
        header.put("Content-Type", "application/json");
        // 设置请求参数
        JSONObject params = new JSONObject();
        params.set("keyIndex", keyIndex);
        String url = "https://" + ip + ":" + port + "/mngapi/asymm/delete";
        // 发送请求
        int retry = 3;
        while (true) {
            String body = HttpUtil.createPost(url)
                    .setConnectionTimeout(5 * 1000)
                    .addHeaders(header)
                    .body(params.toString())
                    .execute()
                    .body();
            JSONObject jsonObject = null;
            try {
                jsonObject = JSONUtil.parseObj(body);
            } catch (Exception e) {
                throw new AFCryptoException("HSM-Dev Error: " + "解析服务器响应失败");
            }
            logger.info("HSM-Dev Response: " + jsonObject.toStringPretty());

            int status = jsonObject.getInt("status");
            if (status == 200) {
                logger.info("HSM-Dev,删除密钥成功,密钥索引:{}", keyIndex);
                return;
            } else {
                if (retry-- > 0) {
                    continue;
                }
                throw new AFCryptoException("HSM-Dev Error: " + jsonObject.getStr("message"));
            }
        }
    }


    //endregion


    //region======================================================获取内部对称密钥句柄 获取连接个数===========================

    /**
     * 获取内部对称密钥句柄
     *
     * @param keyIndex 密钥索引
     * @return 密钥句柄
     */
    public int getSymKeyHandle(int keyIndex) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("获取内部对称密钥句柄，密钥索引必须大于等于0");
            throw new AFCryptoException("获取内部对称密钥句柄，密钥索引必须大于等于0");
        }
        return cmd.getSymKeyHandle(keyIndex);
    }

    /**
     * 获取连接个数
     *
     * @return 连接个数
     */
    public int getConnectCount() throws AFCryptoException {
        return getConnectCount(client);
    }

    //endregion

    //region============================================================工具============================================


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

    /**
     * 从 buf中读取每个解密后的明文 并且批量 cutting
     *
     * @param buf   数据buf
     * @param count 个数
     * @return 明文list, 每个明文都是cutting后的
     */
    private static List<byte[]> getCollect(BytesBuffer buf, int count) {
        return IntStream.range(0, count).mapToObj(i -> {
            try {
                return cutting(buf.readOneData());
            } catch (AFCryptoException e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toList());
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

    //endregion
}
