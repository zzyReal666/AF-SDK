
package com.af.device.impl;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.SM3;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.af.constant.Algorithm;
import com.af.constant.CertParseInfoType;
import com.af.constant.ConstantNumber;
import com.af.constant.ModulusLength;
import com.af.crypto.algorithm.sm3.SM3Impl;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.device.DeviceInfo;
import com.af.device.IAFDevice;
import com.af.device.IAFSVDevice;
import com.af.device.cmd.AFSVCmd;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.netty.NettyClient;
import com.af.nettyNew.NettyClientChannels;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.impl.sm2.SM2Cipher;
import com.af.struct.impl.sm2.SM2Signature;
import com.af.struct.signAndVerify.*;
import com.af.struct.signAndVerify.RSA.RSAKeyPairStructure;
import com.af.struct.signAndVerify.RSA.RSAPrivateKeyStructure;
import com.af.struct.signAndVerify.RSA.RSAPublicKeyStructure;
import com.af.struct.signAndVerify.sm2.*;
import com.af.utils.BigIntegerUtil;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import com.af.utils.base64.Base64;
import com.af.utils.pkcs.AFPkcs1Operate;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 签名验签服务器 设备实现类
 * @since 2023/5/16 9:12
 */
@Getter
@Setter
@ToString
public class AFSVDevice implements IAFSVDevice {

    //region 成员 与构造
    private static final Logger logger = LoggerFactory.getLogger(AFSVDevice.class);

    /**
     * 协商密钥
     */
    private byte[] agKey;
    /**
     * 通信客户端
     */
    @Getter
    private static NettyClient client;
    /**
     * 命令对象
     */
    private final AFSVCmd cmd = new AFSVCmd(client, agKey);

    /**
     * SM3 用于计算摘要
     */
    private static final SM3 sm3 = new SM3();


    private byte[] RSAKey_e = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x01
    };

    //私有构造
    private AFSVDevice() {
    }

    //静态内部类单例
    private static class SingletonHolder {
        private static final AFSVDevice INSTANCE = new AFSVDevice();
    }

    //获取单例
    public static AFSVDevice getInstance(String host, int port, String passwd) {
        client = AFNettyClient.getInstance(host, port, passwd);
        return SingletonHolder.INSTANCE;
    }

    /**
     * 建造者模式
     */
    public static class Builder {
        //region//======>必要参数
        private final String host;
        private final int port;
        private final String passwd;
        //endregion

        //region//======>构造方法
        public Builder(String host, int port, String passwd) {
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
        private int retryInterval = 1000;

        /**
         * 缓冲区大小
         */
        private int bufferSize = 1024 * 1024;

        /**
         * 通道数量
         */
        private int channelCount = 10;

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

        //endregion

        //region//======>build
        public AFSVDevice build() {
            client = new NettyClientChannels.Builder(host, port, passwd, IAFDevice.generateTaskNo())
                    .timeout(connectTimeOut)
                    .responseTimeout(responseTimeOut)
                    .retryCount(retryCount)
                    .retryInterval(retryInterval)
                    .bufferSize(bufferSize)
                    .channelCount(channelCount)
                    .build();
            AFSVDevice afsvDevice = AFSVDevice.SingletonHolder.INSTANCE;
            if (isAgKey) {
                afsvDevice.setAgKey();
            }
            return afsvDevice;
        }
    }
    //endregion


    /**
     * 协商密钥
     */
    public AFSVDevice setAgKey() {
        this.agKey = this.keyAgreement(client);
        this.cmd.setAgKey(this.agKey);
        logger.info("协商密钥成功,密钥:{}", HexUtil.encodeHexStr(this.agKey));
        return this;
    }
    //endregion

    //region 设备信息 获取随机数 私钥访问权限

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * 获取设备信息异常
     */
    @Override
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        return cmd.getDeviceInfo();
    }

    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * 获取随机数异常
     */
    @Override
    public byte[] getRandom(int length) throws AFCryptoException {
        int RAN_MAX_LEN = 4096;
        byte[] output = new byte[length];
        byte[] buff;
        int stepLen;
        for (stepLen = length; stepLen > RAN_MAX_LEN; stepLen -= RAN_MAX_LEN) {
            buff = cmd.getRandom(RAN_MAX_LEN);
            System.arraycopy(buff, 0, output, output.length - stepLen, RAN_MAX_LEN);
        }
        buff = cmd.getRandom(stepLen);
        System.arraycopy(buff, 0, output, output.length - stepLen, stepLen);
        return BytesOperate.base64EncodeData(output);
    }

    /**
     * 获取私钥访问权限
     *
     * @param index   索引
     * @param keyType 密钥类型 3:SM2 4:RSA
     * @param psw     私钥授权码
     */
    public void getPrivateAccess(int index, int keyType, String psw) throws AFCryptoException {
        //region//======>参数检查
        if (index < 0 || index > 0xFFFF) {
            logger.error("密钥索引不合法,索引范围为0-65535,当前索引为:{}", index);
            throw new AFCryptoException("密钥索引不合法");
        }
        if (keyType != 3 && keyType != 4) {
            logger.error("keyType 只能为3或4");
            throw new AFCryptoException("keyType 只能为3(SM2)或4(RSA)");
        }
        cmd.getPrivateAccess(index, keyType, psw);
    }
    //endregion

    //region 导出公钥

    /**
     * 获取SM2签名公钥
     *
     * @param index 索引
     * @return SM2签名公钥 ASN1编码 DER
     */
    public byte[] getSM2SignPublicKey(int index) throws AFCryptoException {
        //参数检查
        if (index <= 0) {
            logger.error("index 需要大于0");
            throw new AFCryptoException("index 需要大于0");
        }
        byte[] bytes = cmd.exportPublicKey(index, Algorithm.SGD_SM2_1);
        logger.info("返回需要对比的数据:" + HexUtil.encodeHexStr(bytes));
        return bytesToASN1SM2PubKey(bytes);
    }

    /**
     * 获取SM2加密公钥
     *
     * @param index 索引
     * @return SM2加密公钥 ASN1编码 DER
     */
    public byte[] getSM2EncryptPublicKey(int index) throws AFCryptoException {
        //参数检查
        if (index <= 0) {
            logger.error("index 需要大于0");
            throw new AFCryptoException("index 需要大于0");
        }
        byte[] bytes = cmd.exportPublicKey(index, Algorithm.SGD_SM2_2);
        logger.info("返回需要对比的数据:" + HexUtil.encodeHexStr(bytes));
        return bytesToASN1SM2PubKey(bytes);
    }

    /**
     * 获取RSA签名公钥信息
     *
     * @param index ：密钥索引
     * @return RSA签名公钥 ASN1编码 DER
     */
    public byte[] getRSASignPublicKey(int index) throws AFCryptoException {
        byte[] bytes = cmd.exportPublicKey(index, Algorithm.SGD_RSA_SIGN);
        return bytesToASN1RSAPubKey(bytes);

    }

    /**
     * 获取RSA加密公钥信息
     *
     * @param index ： 密钥索引
     * @return RSA加密公钥 ASN1编码 DER
     */
    public byte[] getRSAEncPublicKey(int index) throws AFCryptoException {
        //参数检查
        if (index <= 0) {
            logger.error("index 需要大于0");
            throw new AFCryptoException("index 需要大于0");
        }
        byte[] bytes = cmd.exportPublicKey(index, Algorithm.SGD_RSA_ENC);
        return bytesToASN1RSAPubKey(bytes);
    }


    //endregion

    //region 生成密钥对 RSA SM2

    /**
     * 生成密钥对 SM2
     *
     * @param keyType 密钥类型 0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对
     * @return  SM2密钥对 {@link SM2KeyPairStructure}
     */

    public SM2KeyPairStructure generateSM2KeyPair(int keyType) throws AFCryptoException {
        SM2KeyPair sm2KeyPair = new SM2KeyPair();
        //签名密钥对
        if (keyType == ConstantNumber.SGD_SIGN_KEY_PAIR) {
            byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_SM2_1, ModulusLength.LENGTH_256);
            sm2KeyPair.decode(bytes);
        }
        //密钥交换密钥对
        else if (keyType == ConstantNumber.SGD_ENC_KEY_PAIR) {
            byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_SM2_2, ModulusLength.LENGTH_256);
            sm2KeyPair.decode(bytes);

        }
        //加密密钥对
        else if (keyType == ConstantNumber.SGD_EXCHANGE_KEY_PAIR) {
            byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_SM2_3, ModulusLength.LENGTH_256);
            sm2KeyPair.decode(bytes);
        }
        //默认密钥对
        else if (keyType == ConstantNumber.SGD_KEY_PAIR) {
            byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_SM2, ModulusLength.LENGTH_256);
            sm2KeyPair.decode(bytes);
        } else {
            logger.error("密钥类型错误,keyType(0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对)={}", keyType);
            throw new AFCryptoException("密钥类型错误,keyType(0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对)=" + keyType);
        }
        //公钥结构体
        SM2PublicKeyStructure sm2PublicKeyStructure = new SM2PublicKeyStructure(sm2KeyPair.getPubKey().to256());
        //私钥结构体
        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2KeyPair.getPriKey().to256());

        try {
            //公钥结构体编码
            byte[] encodedPubKey = sm2PublicKeyStructure.toASN1Primitive().getEncoded("DER");
            //私钥结构体编码
            byte[] encodedPriKey = sm2PrivateKeyStructure.toASN1Primitive().getEncoded("DER");

            //公钥结构体Base64编码
            byte[] base64PubKey = BytesOperate.base64EncodeData(encodedPubKey);
            //私钥结构体Base64编码
            byte[] base64PriKey = BytesOperate.base64EncodeData(encodedPriKey);

            return new SM2KeyPairStructure(base64PubKey, base64PriKey);

        } catch (IOException e) {
            logger.error("SM2密钥对DER编码失败", e);
            throw new AFCryptoException("SM2密钥对DER编码失败", e);
        }
    }

    /**
     * 生成密钥对 RSA
     *
     * @param length 模长 1024|2048  {@link ModulusLength}
     */

    public RSAKeyPairStructure generateRSAKeyPair(ModulusLength length) throws AFCryptoException {
        //length只能是1024或2048
        if (length != ModulusLength.LENGTH_1024 && length != ModulusLength.LENGTH_2048) {
            logger.error("RSA密钥模长错误,length(1024|2048)={}", length);
            throw new AFCryptoException("RSA密钥模长错误,length(1024|2048)=" + length);
        }
        byte[] bytes = cmd.generateKeyPair(Algorithm.SGD_RSA, length);
        RSAKeyPair rsaKeyPair = new RSAKeyPair(bytes);
        rsaKeyPair.decode(bytes);

        //公钥结构体
        RSAPublicKeyStructure rsaPublicKeyStructure = new RSAPublicKeyStructure(rsaKeyPair.getPubKey());
        //私钥结构体
        RSAPrivateKeyStructure rsaPrivateKeyStructure = new RSAPrivateKeyStructure(rsaKeyPair.getPriKey());

        try {
            //公钥结构体编码
            byte[] encodedPubKey = rsaPublicKeyStructure.toASN1Primitive().getEncoded("DER");
            //私钥结构体编码
            byte[] encodedPriKey = rsaPrivateKeyStructure.toASN1Primitive().getEncoded("DER");
            //公钥结构体Base64编码
            encodedPubKey = BytesOperate.base64EncodeData(encodedPubKey);
            //私钥结构体Base64编码
            encodedPriKey = BytesOperate.base64EncodeData(encodedPriKey);

            return new RSAKeyPairStructure(encodedPubKey, encodedPriKey);
        } catch (IOException e) {
            logger.error("RSA密钥对DER编码失败", e);
            throw new RuntimeException("RSA密钥对DER编码失败", e);
        }
    }
    //endregion

    //region 释放密钥信息

    /**
     * 释放密钥信息
     *
     * @param id 4 字节密钥信息 ID
     */
    public void releaseSessionKey(int id) throws AFCryptoException {
        cmd.freeKey(id);
    }
    //endregion

    //region  RSA计算

    /**
     * RSA 签名 内部私钥
     *
     * @param keyIndex 密钥索引
     * @param inData   待签名数据
     * @return 签名值 Base64 编码
     */
    public byte[] rsaSignature(int keyIndex, byte[] inData) throws AFCryptoException {
        //region//======>参数检查 日志打印
        logger.info("SV-RSA签名, keyIndex: {}, inDataLen: {}", keyIndex, null == inData ? 0 : inData.length);
        if (keyIndex <= 0) {
            logger.error("密钥索引错误,keyIndex={}", keyIndex);
            throw new AFCryptoException("密钥索引错误,keyIndex=" + keyIndex);
        }
        if (inData == null || inData.length == 0) {
            logger.error("待签名数据为空");
            throw new AFCryptoException("待签名数据为空");
        }
        //endregion
//        //获取私钥访问权限
//        getPrivateAccess(keyIndex, 4);
        //获取模长
        int bits = getBitsByKeyIndex(keyIndex);
        //PKCS1 签名填充
        int maxInDataLen = (bits / 8) - 11;
        if (inData.length > maxInDataLen) {
            logger.error("待签名数据长度超过最大长度(可考虑采用文件签名方式), maxInDataLen: {}, inDataLen: {}", maxInDataLen, inData.length);
            throw new AFCryptoException("待签名数据长度超过最大长度(可考虑采用文件签名方式), maxInDataLen=" + maxInDataLen + ", inDataLen=" + inData.length);
        }
        byte[] signData = AFPkcs1Operate.pkcs1EncryptionPrivate(bits, inData);
        //签名 Base64 编码
        byte[] bytes = cmd.rsaPrivateKeyOperation(keyIndex, null, Algorithm.SGD_RSA_SIGN, signData);
        return BytesOperate.base64EncodeData(bytes);
    }


    /**
     * RSA 签名 外部私钥
     *
     * @param privateKey 外部私钥 ASN1结构 Base64编码
     * @param inData     待签名数据
     * @return Base64编码的签名数据
     */
    public byte[] rsaSignature(byte[] privateKey, byte[] inData) throws AFCryptoException {
        logger.info("SV-RSA签名, privateKeyLen: {}, inDataLen: {}", null == privateKey ? 0 : privateKey.length, null == inData ? 0 : inData.length);
        // 参数检查
        if (privateKey == null || privateKey.length == 0) {
            logger.error("外部私钥为空");
            throw new AFCryptoException("外部私钥为空");
        }
        if (inData == null || inData.length == 0) {
            logger.error("待签名数据为空");
            throw new AFCryptoException("待签名数据为空");
        }
        // 解析私钥
        RSAPriKey rsaPriKey = decodeRSAPrivateKey(privateKey);
        // 获取模长
        int modulus = rsaPriKey.getBits();
        // PKCS1 签名填充
        int maxInDataLen = (modulus / 8) - 11;
        if (inData.length > maxInDataLen) {
            logger.error("待签名数据长度超过最大长度(可考虑采用文件签名方式), maxInDataLen: {}, inDataLen: {}", maxInDataLen, inData.length);
            throw new AFCryptoException("待签名数据长度超过最大长度(可考虑采用文件签名方式), maxInDataLen=" + maxInDataLen + ", inDataLen=" + inData.length);
        }
        byte[] bytes = AFPkcs1Operate.pkcs1EncryptionPrivate(modulus, inData);
        // 签名 Base64 编码
        return BytesOperate.base64EncodeData(cmd.rsaPrivateKeyOperation(0, rsaPriKey, Algorithm.SGD_RSA_SIGN, bytes));
    }


    /**
     * RSA 文件签名 内部私钥
     *
     * @param keyIndex 密钥索引
     * @param filePath 文件路径
     * @return 签名值 Base64 编码
     */
    public byte[] rsaSignFile(int keyIndex, byte[] filePath) throws AFCryptoException {
        logger.info("SV-RSA文件签名, keyIndex: {}, fileName: {}", keyIndex, null == filePath ? "" : filePath);
        //参数检查
        if (keyIndex <= 0) {
            logger.error("密钥索引错误,keyIndex={}", keyIndex);
            throw new AFCryptoException("密钥索引错误,keyIndex=" + keyIndex);
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("文件路径为空");
            throw new AFCryptoException("文件路径为空");
        }
        //读取文件 生成文件摘要 SHA256
        byte[] md5Result = fileReadAndDigest(filePath);
        //RSA签名
        return rsaSignature(keyIndex, md5Result);
    }

    /**
     * RSA 文件签名 外部私钥
     *
     * @param privateKey 外部私钥 ASN1结构 Base64编码
     * @param filePath   文件名
     * @return Base64编码的签名数据
     */
    public byte[] rsaSignFile(byte[] privateKey, byte[] filePath) throws AFCryptoException {
        // 参数检查
        if (privateKey == null || privateKey.length == 0) {
            logger.error("外部私钥为空");
            throw new AFCryptoException("外部私钥为空");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("文件名为空");
            throw new AFCryptoException("文件名为空");
        }

        // 读取文件 生成文件摘要 SHA256
        byte[] md5Result = fileReadAndDigest(filePath);
        // RSA签名
        return rsaSignature(privateKey, md5Result);

    }


    /**
     * RSA 验签 内部公钥
     *
     * @param keyIndex      密钥索引
     * @param inData        原始数据
     * @param signatureData Base64编码的签名数据
     * @return true : 验证成功，false ：验证失败
     */
    public boolean rsaVerify(int keyIndex, byte[] inData, byte[] signatureData) throws AFCryptoException {
        //
        //参数检查
        if (keyIndex <= 0) {
            logger.error("密钥索引错误,keyIndex={}", keyIndex);
            throw new AFCryptoException("密钥索引错误,keyIndex=" + keyIndex);
        }
        if (inData == null || inData.length == 0) {
            logger.error("原始数据为空");
            throw new AFCryptoException("原始数据为空");
        }
        if (signatureData == null || signatureData.length == 0) {
            logger.error("签名数据为空");
            throw new AFCryptoException("签名数据为空");
        }
        //Base64解码签名数据
        signatureData = BytesOperate.base64DecodeData(signatureData);
        //RSA验签
        byte[] bytes = cmd.rsaPublicKeyOperation(keyIndex, null, Algorithm.SGD_RSA_SIGN, signatureData);
        //去填充
        int bits = getBitsByKeyIndex(keyIndex);
        bytes = AFPkcs1Operate.pkcs1DecryptionPrivate(bits, bytes);
        //比较签名值
        return Arrays.equals(bytes, inData);
    }


    /**
     * RSA 验签 外部公钥
     *
     * @param publicKey     公钥 ASN1结构 Base64编码
     * @param rawData       原始数据
     * @param signatureData Base64编码的签名数据
     * @return true : 验证成功，false ：验证失败
     */
    public boolean rsaVerify(byte[] publicKey, byte[] rawData, byte[] signatureData) throws AFCryptoException {
        logger.info("SV-RSA验签");
        //参数检查
        if (publicKey == null || publicKey.length == 0) {
            logger.error("公钥为空");
            throw new AFCryptoException("公钥为空");
        }
        if (rawData == null || rawData.length == 0) {
            logger.error("原始数据为空");
            throw new AFCryptoException("原始数据为空");
        }
        if (signatureData == null || signatureData.length == 0) {
            logger.error("签名数据为空");
            throw new AFCryptoException("签名数据为空");
        }
        //解析公钥
        RSAPubKey rsaPubKey = decodeRSAPublicKey(publicKey);
        //Base64解码签名数据
        signatureData = BytesOperate.base64DecodeData(signatureData);
        //RSA验签
        byte[] bytes = cmd.rsaPublicKeyOperation(0, rsaPubKey, Algorithm.SGD_RSA_SIGN, signatureData);
        //去填充
        int bits = rsaPubKey.getBits();
        bytes = AFPkcs1Operate.pkcs1DecryptionPrivate(bits, bytes);
        //比较签名值
        return Arrays.equals(bytes, rawData);
    }


    /**
     * RSA 文件验签  内部公钥
     *
     * @param keyIndex      密钥索引
     * @param filePath      文件路径
     * @param signatureData Base64编码的签名数据
     * @return true : 验证成功，false ：验证失败
     */
    public boolean rsaVerifyFile(int keyIndex, byte[] filePath, byte[] signatureData) throws AFCryptoException {
        logger.info("SV-RSA文件验签");
        //region //======参数检查
        if (keyIndex <= 0) {
            logger.error("密钥索引错误,keyIndex={}", keyIndex);
            throw new AFCryptoException("密钥索引错误,keyIndex=" + keyIndex);
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("文件路径为空");
            throw new AFCryptoException("文件路径为空");
        }
        if (signatureData == null || signatureData.length == 0) {
            logger.error("签名数据为空");
            throw new AFCryptoException("签名数据为空");
        }
        //endregion
        //读取文件 生成文件摘要 SHA256
        byte[] md5Result = fileReadAndDigest(filePath);
        //RSA验签
        return rsaVerify(keyIndex, md5Result, signatureData);
    }

    /**
     * RSA 文件验签 外部公钥
     *
     * @param publicKey     公钥 ASN1结构 Base64编码
     * @param filePath      文件路径
     * @param signatureData Base64编码的签名数据
     * @return true : 验证成功，false ：验证失败
     */
    public boolean rsaVerifyFile(byte[] publicKey, byte[] filePath, byte[] signatureData) throws AFCryptoException {
        logger.info("SV-RSA文件验签");
        //region //======>参数检查
        if (publicKey == null || publicKey.length == 0) {
            logger.error("公钥为空");
            throw new AFCryptoException("公钥为空");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("文件路径为空");
            throw new AFCryptoException("文件路径为空");
        }
        if (signatureData == null || signatureData.length == 0) {
            logger.error("签名数据为空");
            throw new AFCryptoException("签名数据为空");
        }
        //endregion
        //读取文件 生成文件摘要 SHA256
        byte[] md5Result = fileReadAndDigest(filePath);
        //RSA验签
        return rsaVerify(publicKey, md5Result, signatureData);
    }

    /**
     * RSA 证书验签
     *
     * @param certificatePath 证书路径
     * @param inData          原始数据
     * @param signatureData   Base64编码的签名数据
     * @return true : 验证成功，false ：验证失败
     */
    public boolean rsaVerifyByCertificate(byte[] certificatePath, byte[] inData, byte[] signatureData) throws AFCryptoException {
        logger.info("SV-RSA证书验签");
        //region//======>参数检查
        if (certificatePath == null || certificatePath.length == 0) {
            logger.error("证书为空");
            throw new AFCryptoException("证书为空");
        }
        if (inData == null || inData.length == 0) {
            logger.error("原始数据为空");
            throw new AFCryptoException("原始数据为空");
        }
        if (signatureData == null || signatureData.length == 0) {
            logger.error("签名数据为空");
            throw new AFCryptoException("签名数据为空");
        }
        //endregion
        //获取证书中的公钥
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificatePath(certificatePath);
        return rsaVerify(rsaPubKey.encode(), inData, signatureData);
    }

    /**
     * RSA 证书文件验签
     *
     * @param certificatePath 证书路径
     * @param filePath        文件路径
     * @param signatureData   Base64编码的签名数据
     * @return true : 验证成功，false ：验证失败
     */
    public boolean rsaVerifyFileByCertificate(byte[] certificatePath, byte[] filePath, byte[] signatureData) throws AFCryptoException {
        logger.info("SV-RSA证书文件验签");
        //region//======>参数检查
        if (certificatePath == null || certificatePath.length == 0) {
            logger.error("证书为空");
            throw new AFCryptoException("证书为空");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("文件路径为空");
            throw new AFCryptoException("文件路径为空");
        }
        if (signatureData == null || signatureData.length == 0) {
            logger.error("签名数据为空");
            throw new AFCryptoException("签名数据为空");
        }
        //endregion
        //读取证书中的公钥
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificatePath(certificatePath);
        //外部公钥文件验签
        return rsaVerifyFile(rsaPubKey.encode(), filePath, signatureData);
    }

    /**
     * RSA加密 内部公钥
     *
     * @param keyIndex 密钥索引
     * @param data     待加密数据
     * @return Base64编码的加密数据
     */
    public byte[] rsaEncrypt(int keyIndex, byte[] data) throws AFCryptoException {
        logger.info("SV-RSA加密-内部公钥");
        //region//======>参数检查
        if (keyIndex <= 0) {
            logger.error("密钥索引错误,keyIndex={}", keyIndex);
            throw new AFCryptoException("密钥索引错误,keyIndex=" + keyIndex);
        }
        if (data == null || data.length == 0) {
            logger.error("原始数据为空");
            throw new AFCryptoException("原始数据为空");
        }
        //endregion
        //模长
        int bits = getBitsByKeyIndex(keyIndex);
        //RSA加密PKCS1填充
        data = AFPkcs1Operate.pkcs1EncryptionPublicKey(bits, data);
        //RSA加密
        byte[] rsaEncrypt = cmd.rsaPublicKeyOperation(keyIndex, null, Algorithm.SGD_RSA_ENC, data);
        //返回Base64编码的加密数据
        return BytesOperate.base64EncodeData(rsaEncrypt);

    }

    /**
     * RSA加密 外部公钥
     *
     * @param publicKey 公钥 ASN1结构 Base64编码
     * @param data      待加密数据
     * @return Base64编码的加密数据
     */
    public byte[] rsaEncrypt(byte[] publicKey, byte[] data) throws AFCryptoException {
        logger.info("SV-RSA加密-外部公钥");
        //region//======>参数检查
        if (publicKey == null || publicKey.length == 0) {
            logger.error("公钥为空");
            throw new AFCryptoException("公钥为空");
        }
        if (data == null || data.length == 0) {
            logger.error("原始数据为空");
            throw new AFCryptoException("原始数据为空");
        }
        //endregion
        //解析公钥
        RSAPubKey rsaPubKey = decodeRSAPublicKey(publicKey);
        //RSA加密PKCS1填充
        data = AFPkcs1Operate.pkcs1EncryptionPublicKey(rsaPubKey.getBits(), data);
        //RSA加密
        byte[] rsaEncrypt = cmd.rsaPublicKeyOperation(0, rsaPubKey, Algorithm.SGD_RSA_ENC, data);
        //返回Base64编码的加密数据
        return BytesOperate.base64EncodeData(rsaEncrypt);
    }


    /**
     * RSA 加密 证书公钥
     *
     * @param certificatePath 证书路径
     * @param data            待加密数据
     * @return Base64编码的加密数据
     */
    public byte[] rsaEncryptByCertificate(byte[] certificatePath, byte[] data) throws AFCryptoException {
        logger.info("SV-RSA加密-证书公钥");
        //region//======>参数检查
        if (certificatePath == null || certificatePath.length == 0) {
            logger.error("证书路径为空");
            throw new AFCryptoException("证书路径为空");
        }
        if (data == null || data.length == 0) {
            logger.error("原始数据为空");
            throw new AFCryptoException("原始数据为空");
        }
        //读取证书中的公钥
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificatePath(certificatePath);
        //RSA加密PKCS1填充
        data = AFPkcs1Operate.pkcs1EncryptionPublicKey(rsaPubKey.getBits(), data);
        //RSA加密
        byte[] rsaEncrypt = cmd.rsaPublicKeyOperation(0, rsaPubKey, Algorithm.SGD_RSA_ENC, data);
        //返回Base64编码的加密数据
        return BytesOperate.base64EncodeData(rsaEncrypt);
    }

    /**
     * RSA解密 内部私钥
     *
     * @param keyIndex 密钥索引
     * @param encData  Base64编码的加密数据
     * @return 解密数据 Base64编码
     */
    public byte[] rsaDecrypt(int keyIndex, byte[] encData) throws AFCryptoException {
        logger.info("SV-RSA解密-内部私钥");
        //region//======>参数检查
        if (keyIndex <= 0) {
            logger.error("密钥索引错误,keyIndex={}", keyIndex);
            throw new AFCryptoException("密钥索引错误,keyIndex=" + keyIndex);
        }
        if (encData == null || encData.length == 0) {
            logger.error("加密数据为空");
            throw new AFCryptoException("加密数据为空");
        }
        //endregion
        //Base64解码
        encData = BytesOperate.base64DecodeData(encData);
        //RSA解密
        byte[] rsaDecrypt = cmd.rsaPrivateKeyOperation(keyIndex, null, Algorithm.SGD_RSA_ENC, encData);
        //获取模长
        int bits = getBitsByKeyIndex(keyIndex);
        //RSA解密PKCS1去填充
        //返回解密数据 Base64编码
        return AFPkcs1Operate.pkcs1DecryptPublicKey(bits, rsaDecrypt);
    }


    /**
     * RSA解密 外部私钥
     *
     * @param privateKey 私钥 ASN1结构 Base64编码
     * @param encData    Base64编码的加密数据
     * @return 解密数据 Base64编码
     */
    public byte[] rsaDecrypt(byte[] privateKey, byte[] encData) throws AFCryptoException {
        logger.info("SV-RSA解密-外部私钥");
        //region//======>参数检查
        if (privateKey == null || privateKey.length == 0) {
            logger.error("私钥为空");
            throw new AFCryptoException("私钥为空");
        }
        if (encData == null || encData.length == 0) {
            logger.error("加密数据为空");
            throw new AFCryptoException("加密数据为空");
        }
        //endregion
        //解析私钥
        RSAPriKey rsaPriKey = decodeRSAPrivateKey(privateKey);
        //Base64解码
        encData = BytesOperate.base64DecodeData(encData);
        //RSA解密
        byte[] rsaDecrypt = cmd.rsaPrivateKeyOperation(0, rsaPriKey, Algorithm.SGD_RSA_ENC, encData);
        //RSA解密PKCS1去填充
        //返回解密数据 Base64编码
        return AFPkcs1Operate.pkcs1DecryptPublicKey(rsaPriKey.getBits(), rsaDecrypt);
    }

    //endregion

    //region SM2计算

    /**
     * SM2 签名 内部密钥
     *
     * @param index 密钥索引
     * @param data  待签名数据
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2Signature(int index, byte[] data) throws AFCryptoException {
        //region//======>参数检查
        logger.info("SV-SM2签名-内部密钥");
        if (index <= 0) {
            logger.error("密钥索引错误,index={}", index);
            throw new AFCryptoException("密钥索引错误,index=" + index);
        }
        if (data == null || data.length == 0) {
            logger.error("待签名的数据为空");
            throw new AFCryptoException("待签名的数据为空");
        }
        //endregion
//        //获取私钥访问权限
//        cmd.getPrivateAccess(index, 3);
        //SM3杂凑
        byte[] digest = sm3.digest(data);
        //SM2签名
        byte[] bytes = cmd.sm2Sign(index, null, digest);
        // AF结构
        SM2Signature sm2Signature = new SM2Signature(bytes).to256();
        // ASN1结构
        SM2SignStructure sm2SignStructure = new SM2SignStructure(sm2Signature);
        // DER编码
        byte[] encoded;
        try {
            encoded = sm2SignStructure.toASN1Primitive().getEncoded("DER");
        } catch (IOException e) {
            logger.error("SM2签名DER编码失败", e);
            throw new AFCryptoException("SM2签名DER编码失败");
        }
        return BytesOperate.base64EncodeData(encoded);
    }

    /**
     * SM2 签名 外部密钥
     * 不带z值
     *
     * @param privateKey 私钥 ASN1结构 Base64编码
     * @param data       待签名数据
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2Signature(byte[] privateKey, byte[] data) throws AFCryptoException {
        //region//======>参数检查
        logger.info("SV-SM2签名-外部密钥");
        if (privateKey == null || privateKey.length == 0) {
            logger.error("私钥为空");
            throw new AFCryptoException("私钥为空");
        }
        if (data == null || data.length == 0) {
            logger.error("待签名的数据为空");
            throw new AFCryptoException("待签名的数据为空");
        }
        //endregion
        try {
            //解析私钥
            SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(privateKey).to512();
            byte[] encodeKey = sm2PrivateKey.encode();
            //SM3杂凑
            data = sm3.digest(data);
            //SM2签名
            byte[] bytes = cmd.sm2Sign(-1, encodeKey, data);
            SM2Signature sm2Signature = new SM2Signature(bytes).to256();
            SM2SignStructure sm2SignStructure = new SM2SignStructure(sm2Signature);                              // 转换为ASN1结构
            return BytesOperate.base64EncodeData(sm2SignStructure.toASN1Primitive().getEncoded("DER"));       // DER编码 base64编码
        } catch (IOException e) {
            logger.error("SM2外部密钥签名失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * SM2 签名 外部私钥 (根据私钥计算出公钥) 公钥Hash,私钥签名
     * 带z值
     *
     * @param privateKey 私钥 ASN1结构 Base64编码
     * @param data       待签名数据
     */
    public byte[] sm2SignatureByPrivateKey(byte[] privateKey, byte[] data) throws AFCryptoException {
        logger.info("SM2-签名-外部私钥");
        if (privateKey == null || privateKey.length == 0) {
            logger.error("SM2-签名-外部私钥,私钥为空");
            throw new AFCryptoException("SM2-签名-外部私钥,私钥为空");
        }
        if (data == null || data.length == 0) {
            logger.error("SM2-签名-外部私钥,待签名的数据为空");
            throw new AFCryptoException("SM2-签名-外部私钥,待签名的数据为空");
        }
        //解析私钥 为AF结构
        SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(privateKey).to512();
        //计算公钥
        byte[] sm2PubKeyFromPriKey = getSM2PubKeyFromPriKey(privateKey);
        //解析公钥 为AF结构
        SM2PublicKey sm2PublicKey = structureToSM2PubKey(sm2PubKeyFromPriKey).to512();
        //SM3杂凑
        SM3Impl sm3 = new SM3Impl();
        data = sm3.SM3HashWithPublicKey256(data, sm2PublicKey, ConstantNumber.DEFAULT_USER_ID.getBytes());
        //SM2签名
        byte[] bytes = cmd.sm2Sign(-1, sm2PrivateKey.encode(), data);
        // AF结构
        SM2Signature sm2Signature = new SM2Signature(bytes).to256();
        // ASN1结构
        SM2SignStructure sm2SignStructure = new SM2SignStructure(sm2Signature);
        // DER编码
        byte[] encoded;
        try {
            encoded = sm2SignStructure.toASN1Primitive().getEncoded("DER");
        } catch (IOException e) {
            logger.error("SM2签名DER编码失败", e);
            throw new AFCryptoException(e);
        }
        return BytesOperate.base64EncodeData(encoded);
    }

    /**
     * SM2 签名 外部私钥+证书  公钥Hash,私钥签名 带z值
     *
     * @param data              待签名数据
     * @param privateKey        私钥 ASN1结构 Base64编码
     * @param base64Certificate 证书  Base64编码
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2SignatureByCertificate(byte[] privateKey, byte[] data, byte[] base64Certificate) throws AFCryptoException {
        logger.info("SV-SM2签名-外部证书");
        //region//======>参数检查
        if (privateKey == null || privateKey.length == 0) {
            logger.error("私钥为空");
            throw new AFCryptoException("私钥为空");
        }
        if (data == null || data.length == 0) {
            logger.error("待签名的数据为空");
            throw new AFCryptoException("待签名的数据为空");
        }
        if (base64Certificate == null || base64Certificate.length == 0) {
            logger.error("证书为空");
            throw new AFCryptoException("证书为空");
        }
        //endregion
        //解析私钥
        SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(privateKey).to512();
        //从证书中解析出公钥
        SM2PublicKey sm2PublicKey = parseSM2PublicKeyFromCert(base64Certificate);
        //对数据进行SM3杂凑 带公钥方式 todo 带公钥方式能否优化为hutool?
        SM3Impl sm3 = new SM3Impl();
        data = sm3.SM3HashWithPublicKey256(data, sm2PublicKey, ConstantNumber.DEFAULT_USER_ID.getBytes());
        //SM2签名
        byte[] bytes = cmd.sm2Sign(-1, sm2PrivateKey.encode(), data);
        // AF结构
        SM2Signature sm2Signature = new SM2Signature(bytes).to256();
        // ASN1结构
        SM2SignStructure sm2SignStructure = new SM2SignStructure(sm2Signature);
        // DER编码
        byte[] encoded;
        try {
            encoded = sm2SignStructure.toASN1Primitive().getEncoded("DER");
        } catch (IOException e) {
            logger.error("SM2签名DER编码失败", e);
            throw new AFCryptoException(e);
        }
        return BytesOperate.base64EncodeData(encoded);

    }


    /**
     * SM2 文件签名 内部密钥
     *
     * @param index    内部密钥索引
     * @param filePath 待签名文件路径
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2SignFile(int index, byte[] filePath) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (index < 0) {
            logger.error("SV_Device 内部密钥文件签名,待签名的签名服务器内部密钥索引小于0");
            throw new AFCryptoException("SV_Device 内部密钥文件签名,待签名的签名服务器内部密钥索引小于0");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("SV_Device 内部密钥文件签名,待签名的文件名称为空");
            throw new AFCryptoException("SV_Device 内部密钥文件签名,待签名的文件名称为空");
        }
        logger.info("SV_Device 内部密钥文件签名,index:{},filePath:{}", index, new String(filePath));
        //endregion
//        //获取私钥访问权限
//        cmd.getPrivateAccess(index, 4);
        // 读取文件内容
        byte[] bytes = FileUtil.readBytes(new String(filePath));
        //SM2签名
        return sm2Signature(index, bytes);
    }

    /**
     * SM2 文件签名 外部密钥
     *
     * @param privateKey 外部密钥 Base64编码 ASN1结构
     * @param filePath   待签名文件路径
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2SignFile(byte[] privateKey, byte[] filePath) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (privateKey == null || privateKey.length == 0) {
            logger.error("SV_Device 外部密钥文件签名,私钥为空");
            throw new AFCryptoException("SV_Device 外部密钥文件签名,私钥为空");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("SV_Device 外部密钥文件签名,待签名的文件名称为空");
            throw new AFCryptoException("SV_Device 外部密钥文件签名,待签名的文件名称为空");
        }
        logger.info("SV_Device 外部密钥文件签名,filePath:{}", new String(filePath));
        //endregion
        // 读取文件内容
        byte[] bytes = FileUtil.readBytes(new String(filePath));
        //SM2签名
        return sm2Signature(privateKey, bytes);
    }

    /**
     * SM2 文件签名 外部私钥 不带证书
     * 带Z值
     *
     * @param privateKey 外部私钥 Base64编码 ASN1结构
     * @param filePath   待签名文件路径
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2SignFileByPrivateKey(byte[] privateKey, byte[] filePath) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (filePath == null || filePath.length == 0) {
            logger.error("SV_Device 外部私钥文件签名,待签名的文件名称为空");
            throw new AFCryptoException("SV_Device 外部私钥文件签名,待签名的文件名称为空");
        }
        if (privateKey == null || privateKey.length == 0) {
            logger.error("SV_Device 外部私钥文件签名,私钥为空");
            throw new AFCryptoException("SV_Device 外部私钥文件签名,私钥为空");
        }
        logger.info("SV_Device 外部私钥文件签名,filePath:{}", new String(filePath));
        //endregion
        // 读取文件内容
        byte[] bytes = FileUtil.readBytes(new String(filePath));
        //SM2签名 带Z值
        return sm2SignatureByPrivateKey(privateKey, bytes);
    }


    /**
     * SM2 文件签名 外部私钥 +证书  带Z值
     *
     * @param filePath          待签名文件路径
     * @param privateKey        外部密钥 Base64编码 ASN1结构
     * @param base64Certificate 证书 Base64编码 用于获取公钥,并做SM3杂凑
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2SignFileByCertificate(byte[] privateKey, byte[] filePath, byte[] base64Certificate) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (filePath == null || filePath.length == 0) {
            logger.error("SV_Device 外部证书文件签名,待签名的文件名称为空");
            throw new AFCryptoException("SV_Device 外部证书文件签名,待签名的文件名称为空");
        }
        if (privateKey == null || privateKey.length == 0) {
            logger.error("SV_Device 外部证书文件签名,私钥为空");
            throw new AFCryptoException("SV_Device 外部证书文件签名,私钥为空");
        }
        if (base64Certificate == null || base64Certificate.length == 0) {
            logger.error("SV_Device 外部证书文件签名,证书为空");
            throw new AFCryptoException("SV_Device 外部证书文件签名,证书为空");
        }
        logger.info("SV_Device 外部证书文件签名,filePath:{}", new String(filePath));
        //endregion
        // 读取文件内容
        byte[] bytes = FileUtil.readBytes(new String(filePath));
        //SM2签名
        return sm2SignatureByCertificate(privateKey, bytes, base64Certificate);
    }

    /**
     * SM2 内部密钥验签
     *
     * @param keyIndex  内部密钥索引
     * @param data      待验签数据
     * @param signature 签名数据 Base64编码 ASN1 DER结构
     * @return true 验签成功 false 验签失败
     */
    public boolean sm2Verify(int keyIndex, byte[] data, byte[] signature) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (keyIndex < 0) {
            logger.error("SV_Device 内部密钥验签,待验签的签名服务器内部密钥索引小于0");
            throw new AFCryptoException("SV_Device 内部密钥验签,待验签的签名服务器内部密钥索引小于0");
        }
        if (data == null || data.length == 0) {
            logger.error("SV_Device 内部密钥验签,待验签数据为空");
            throw new AFCryptoException("SV_Device 内部密钥验签,待验签数据为空");
        }
        if (signature == null || signature.length == 0) {
            logger.error("SV_Device 内部密钥验签,签名数据为空");
            throw new AFCryptoException("SV_Device 内部密钥验签,签名数据为空");
        }
        logger.info("SV_Device 内部密钥验签,index:{}", keyIndex);
        //endregion
        //签名值由Base64编码的ASN1 DER结构转化为AF结构
        signature = convertToSM2Signature(signature).to512().encode();
        //原始数据SM3杂凑
        data = sm3.digest(data);
        //验签
        return cmd.sm2Verify(keyIndex, null, data, signature);


    }

    /**
     * SM2 外部密钥验签
     * 不带z值
     *
     * @param publicKey 外部公钥 Base64编码 ASN1结构
     * @param data      待验签数据
     * @param signature 签名数据 Base64编码 ASN1 DER结构
     * @return true 验签成功 false 验签失败
     */
    public boolean sm2Verify(byte[] publicKey, byte[] data, byte[] signature) throws AFCryptoException {
        //region//======>参数检查 日志打印
        logger.info("SV_Device 外部密钥验签");
        if (publicKey == null || publicKey.length == 0) {
            logger.error("SV_Device 外部密钥验签,公钥为空");
            throw new AFCryptoException("SV_Device 外部密钥验签,公钥为空");
        }
        if (data == null || data.length == 0) {
            logger.error("SV_Device 外部密钥验签,待验签数据为空");
            throw new AFCryptoException("SV_Device 外部密钥验签,待验签数据为空");
        }
        if (signature == null || signature.length == 0) {
            logger.error("SV_Device 外部密钥验签,签名数据为空");
            throw new AFCryptoException("SV_Device 外部密钥验签,签名数据为空");
        }
        //endregion
        //签名值由Base64编码的ASN1 DER结构转化为AF结构
        signature = convertToSM2Signature(signature).to512().encode();
        //原始数据SM3杂凑
        data = sm3.digest(data);
        //解析公钥
        SM2PublicKey sm2PublicKey = structureToSM2PubKey(publicKey);
        //验签
        return cmd.sm2Verify(-1, sm2PublicKey.encode(), data, signature);
    }

    /**
     * SM2 验签 一张证书 带z值
     *
     * @param cert      证书
     * @param data      待验签数据
     * @param signature 签名数据 Base64编码 ASN1 DER结构
     * @return true 验签成功 false 验签失败
     */
    public boolean sm2VerifyByCertificate(byte[] cert, byte[] data, byte[] signature) throws AFCryptoException {
        //region//======>参数检查 日志打印
        logger.info("SV_Device 基于证书的SM2验证签名");
        if (cert == null || cert.length == 0) {
            logger.error("SV_Device 基于证书的SM2验证签名,待验证签名的外部证书为空");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,待验证签名的外部证书为空");
        }
        if (data == null || data.length == 0) {
            logger.error("SV_Device 基于证书的SM2验证签名,待验证签名数据为空");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,待验证签名数据为空");
        }
        if (signature == null || signature.length == 0) {
            logger.error("SV_Device 基于证书的SM2验证签名,待验证签名数据为空");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,待验证签名数据为空");
        }
        //endregion
        //验证证书有效性
        if (0 != validateCertificate(cert)) {
            logger.error("SV_Device 基于证书的SM2验证签名,证书验证失败");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,证书验证不通过");
        }
        //读取证书中的公钥
        SM2PublicKey sm2PublicKey = parseSM2PublicKeyFromCert(cert);
        //签名值由Base64编码的ASN1 DER结构转化为AF结构
        signature = convertToSM2Signature(signature).to512().encode();
        //原始数据SM3杂凑 带公钥
        data = new SM3Impl().SM3HashWithPublicKey256(data, sm2PublicKey, ConstantNumber.DEFAULT_USER_ID.getBytes());
        //验签
        return cmd.sm2Verify(-1, sm2PublicKey.encode(), data, signature);
    }

    /**
     * SM2 验签 两张证书 带Z值
     *
     * @param signCert 签名证书 Base64编码 DER格式
     * @param hashCert 杂凑证书 Base64编码 DER格式
     * @param data     原始数据
     * @param signData 签名数据 Base64编码 ASN1 DER结构
     */
    public boolean sm2VerifyByCertificate(byte[] signCert, byte[] hashCert, byte[] data, byte[] signData) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (signCert == null || signCert.length == 0) {
            logger.error("SV_Device 基于证书的SM2验证签名,待验证签名的外部证书为空");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,待验证签名的外部证书为空");
        }
        if (hashCert == null || hashCert.length == 0) {
            logger.error("SV_Device 基于证书的SM2验证签名,待验证签名的外部证书为空");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,待验证签名的外部证书为空");
        }
        if (data == null || data.length == 0) {
            logger.error("SV_Device 基于证书的SM2验证签名,待验证签名数据为空");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,待验证签名数据为空");
        }
        if (signData == null || signData.length == 0) {
            logger.error("SV_Device 基于证书的SM2验证签名,待验证签名数据为空");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,待验证签名数据为空");
        }
        logger.info("SV_Device 基于证书的SM2验证签名");
        //endregion
        //验证证书有效性
        if (0 != validateCertificate(signCert)) {
            logger.error("SV_Device 基于证书的SM2验证签名,签名证书验证失败");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,签名证书验证失败");
        }
        if (0 != validateCertificate(hashCert)) {
            logger.error("SV_Device 基于证书的SM2验证签名,杂凑证书验证失败");
            throw new AFCryptoException("SV_Device 基于证书的SM2验证签名,杂凑证书验证失败");
        }
        //读取签名证书的公钥
        SM2PublicKey sigKey = parseSM2PublicKeyFromCert(signCert);
        //读取hash证书中的公钥
        SM2PublicKey hashKey = parseSM2PublicKeyFromCert(hashCert);
        //签名值由Base64编码的ASN1 DER结构转化为AF结构
        signData = convertToSM2Signature(signData).to512().encode();
        //原始数据SM3杂凑 带公钥
        data = new SM3Impl().SM3HashWithPublicKey256(data, hashKey, ConstantNumber.DEFAULT_USER_ID.getBytes());
        //验签
        return cmd.sm2Verify(-1, sigKey.encode(), data, signData);
    }


    /**
     * SM2 验证文件签名 内部公钥
     *
     * @param keyIndex  内部密钥索引
     * @param filePath  待验证签名文件路径
     * @param signature 签名数据
     * @return true:验证成功 false:验证失败
     */
    public boolean sm2VerifyFile(int keyIndex, byte[] filePath, byte[] signature) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (keyIndex < 0) {
            logger.error("SM2内部密钥验证文件签名失败,签名服务器内部密钥索引不能小于0");
            throw new AFCryptoException("SM2内部密钥验证文件签名失败,签名服务器内部密钥索引不能小于0");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("SM2内部密钥验证文件签名失败,待验证签名数据为空");
            throw new AFCryptoException("SM2内部密钥验证文件签名失败,待验证签名数据为空");
        }
        if (signature == null || signature.length == 0) {
            logger.error("SM2内部密钥验证文件签名失败,待验证签名数据为空");
            throw new AFCryptoException("SM2内部密钥验证文件签名失败,待验证签名数据为空");
        }
        logger.info("SM2内部密钥验证文件签名,签名服务器内部密钥索引:{}, 待验证签名文件路径:{}", keyIndex, new String(filePath));
        //endregion
        //读取文件
        byte[] bytes = FileUtil.readBytes(new String(filePath));
        //SM3摘要
        byte[] digest = sm3.digest(bytes);
        //签名数据转换为SM2Signature
        SM2Signature sm2Sign = convertToSM2Signature(signature);
        //SM2验证签名
        return cmd.sm2Verify(keyIndex, null, digest, sm2Sign.encode());
    }

    /**
     * SM2 验证文件签名 外部公钥
     *
     * @param sm2PublicKey 外部公钥 Base64编码 ASN1 DER 格式
     * @param filePath     待验证签名文件路径
     * @param signature    签名数据 Base64编码 ASN1 DER 格式
     * @return true:验证成功 false:验证失败
     */
    public boolean sm2VerifyFile(byte[] sm2PublicKey, byte[] filePath, byte[] signature) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (sm2PublicKey == null || sm2PublicKey.length == 0) {
            logger.error("SM2外部密钥验证文件签名失败,待验证签名数据为空");
            throw new AFCryptoException("SM2外部密钥验证文件签名失败,待验证签名数据为空");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("SM2外部密钥验证文件签名失败,待验证签名数据为空");
            throw new AFCryptoException("SM2外部密钥验证文件签名失败,待验证签名数据为空");
        }
        if (signature == null || signature.length == 0) {
            logger.error("SM2外部密钥验证文件签名失败,待验证签名数据为空");
            throw new AFCryptoException("SM2外部密钥验证文件签名失败,待验证签名数据为空");
        }
        logger.info("SM2外部密钥验证文件签名,待验证签名文件路径:{}", new String(filePath));
        //endregion
        //读取文件
        byte[] bytes = FileUtil.readBytes(new String(filePath));
        //SM2验证签名
        return sm2Verify(sm2PublicKey, bytes, signature);
    }

    /**
     * SM2 验证文件签名 一张证书
     *
     * @param base64Certificate 证书  Base64编码
     * @param filePath          待验证签名文件路径
     * @param signature         签名数据 Base64编码 ASN1 DER 格式
     * @return true:验证成功 false:验证失败
     */
    public boolean sm2VerifyFileByCertificate(byte[] base64Certificate, byte[] filePath, byte[] signature) throws AFCryptoException {
        //region//======>参数检查
        if (base64Certificate == null || base64Certificate.length == 0) {
            logger.error("基于证书的SM2验证文件签名失败,待验证签名的外部证书为空");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,待验证签名的外部证书为空");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("基于证书的SM2验证文件签名失败,待验证签名文件路径为空");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,待验证签名文件路径为空");
        }
        if (signature == null || signature.length == 0) {
            logger.error("基于证书的SM2验证文件签名失败,待验证签名数据为空");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,待验证签名数据为空");
        }
        logger.info("基于证书的SM2验证文件签名,待验证签名的外部证书:{}, 待验证签名文件路径:{}", new String(base64Certificate), new String(filePath));
        //endregion
        //验证证书有效性
        if (0 != validateCertificate(base64Certificate)) {
            logger.error("基于证书的SM2验证文件签名失败,待验证签名的外部证书无效");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,待验证签名的外部证书无效");
        }

        //读取文件
        byte[] bytes = FileUtil.readBytes(new String(filePath));
        //ASN1签名转换为SM2Signature
        SM2Signature sm2Sign = convertToSM2Signature(signature);
        //从证书中解析出公钥
        SM2PublicKey sm2PublicKey = parseSM2PublicKeyFromCert(base64Certificate);
        //SM3摘要 带公钥
        byte[] digest = new SM3Impl().SM3HashWithPublicKey256(bytes, sm2PublicKey, ConstantNumber.DEFAULT_USER_ID.getBytes());
        //SM2验证签名
        return cmd.sm2Verify(-1, sm2PublicKey.encode(), digest, sm2Sign.encode());

    }

    /**
     * SM2 验证文件签名 两张证书
     *
     * @param signCert  签名证书 Base64编码
     * @param hashCert  hash证书 Base64编码
     * @param filePath  待验证签名文件路径
     * @param signature 签名数据 Base64编码 ASN1 DER 格式
     * @return true:验证成功 false:验证失败
     */
    public boolean sm2VerifyFileByCertificate(byte[] signCert, byte[] hashCert, byte[] filePath, byte[] signature) throws AFCryptoException {
        //region//======>参数检查
        if (signCert == null || signCert.length == 0) {
            logger.error("基于证书的SM2验证文件签名失败,签名证书为空");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,签名证书为空");
        }
        if (hashCert == null || hashCert.length == 0) {
            logger.error("基于证书的SM2验证文件签名失败,hash证书为空");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,hash证书为空");
        }
        if (filePath == null || filePath.length == 0) {
            logger.error("基于证书的SM2验证文件签名失败,待验证签名文件路径为空");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,待验证签名文件路径为空");
        }
        if (signature == null || signature.length == 0) {
            logger.error("基于证书的SM2验证文件签名失败,待验证签名数据为空");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,待验证签名数据为空");
        }
        logger.info("基于证书的SM2验证文件签名,待验证签名的外部证书:{}, 待验证签名文件路径:{}", new String(signCert), new String(filePath));
        //endregion
        //验证证书有效性
        if (0 != validateCertificate(signCert)) {
            logger.error("基于证书的SM2验证文件签名失败,签名证书无效");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,签名证书无效");
        }
        if (0 != validateCertificate(hashCert)) {
            logger.error("基于证书的SM2验证文件签名失败,hash证书无效");
            throw new AFCryptoException("基于证书的SM2验证文件签名失败,hash证书无效");
        }
        //读取文件
        byte[] bytes = FileUtil.readBytes(new String(filePath));
        //ASN1签名转换为SM2Signature
        SM2Signature sm2Sign = convertToSM2Signature(signature).to512();
        //从证书中解析公钥
        SM2PublicKey signKey = parseSM2PublicKeyFromCert(signCert);
        SM2PublicKey hashKey = parseSM2PublicKeyFromCert(hashCert);
        //SM3摘要 带公钥
        byte[] digest = new SM3Impl().SM3HashWithPublicKey256(bytes, hashKey, ConstantNumber.DEFAULT_USER_ID.getBytes());
        //SM2验证签名
        return cmd.sm2Verify(-1, signKey.encode(), digest, sm2Sign.encode());


    }


    /**
     * SM2 加密 内部公钥
     *
     * @param keyIndex 密钥索引
     * @param inData   待加密数据
     * @return 加密后的数据 base64编码的 ASN1 DER编码
     */
    public byte[] sm2Encrypt(int keyIndex, byte[] inData) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (keyIndex < 0) {
            logger.error("SM2内部密钥加密失败,密钥索引非法");
            throw new AFCryptoException("SM2内部密钥加密失败,密钥索引非法");
        }
        if (inData == null || inData.length == 0) {
            logger.error("SM2内部密钥加密失败,待加密数据为空");
            throw new AFCryptoException("SM2内部密钥加密失败,待加密数据为空");
        }
        logger.info("SM2内部密钥加密,密钥索引:{}, 待加密数据:{}", keyIndex, new String(inData));
        //endregion

        //SM2加密
        byte[] bytes = cmd.sm2Encrypt(keyIndex, null, inData);
        SM2Cipher sm2Cipher = new SM2Cipher(bytes).to256();
        //SM2加密结果转换为ASN1编码
        SM2CipherStructure sm2CipherStructure = new SM2CipherStructure(sm2Cipher);
        //ASN1编码转换为DER编码
        byte[] encoded;
        try {
            encoded = sm2CipherStructure.toASN1Primitive().getEncoded("DER");
        } catch (IOException e) {
            logger.error("SM2内部密钥加密失败,DER编码转换异常:{}", e.getMessage());
            throw new AFCryptoException("SM2内部密钥加密失败,DER编码转换异常:" + e.getMessage());
        }
        return BytesOperate.base64EncodeData(encoded);
    }


    /**
     * SM2 加密 外部公钥
     *
     * @param publicKey 外部公钥 Base64编码的 ASN1 DER结构
     * @param inData    待加密数据
     * @return 加密后的数据 base64编码的 ASN1 DER编码
     */
    public byte[] sm2Encrypt(byte[] publicKey, byte[] inData) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (publicKey == null || publicKey.length == 0) {
            logger.error("SM2外部公钥加密失败,公钥数据为空");
            throw new AFCryptoException("SM2外部公钥加密失败,公钥数据为空");
        }
        if (inData == null || inData.length == 0) {
            logger.error("SM2外部公钥加密失败,待加密数据为空");
            throw new AFCryptoException("SM2外部公钥加密失败,待加密数据为空");
        }
        logger.info("SM2外部公钥加密,公钥数据:{}, 待加密数据:{}", new String(publicKey), new String(inData));
        //endregion
        //公钥转换为SM2PublicKey对象
        SM2PublicKey sm2PublicKey = structureToSM2PubKey(publicKey).to512();
        //SM2加密
        byte[] bytes = cmd.sm2Encrypt(-1, sm2PublicKey.encode(), inData);
        SM2Cipher sm2Cipher = new SM2Cipher(bytes).to256();
        //SM2加密结果转换为ASN1编码
        SM2CipherStructure sm2CipherStructure = new SM2CipherStructure(sm2Cipher);
        //ASN1编码转换为DER编码
        byte[] encoded;
        try {
            encoded = sm2CipherStructure.toASN1Primitive().getEncoded("DER");
        } catch (IOException e) {
            logger.error("SM2外部公钥加密失败,DER编码转换异常:{}", e.getMessage());
            throw new AFCryptoException("SM2外部公钥加密失败,DER编码转换异常:" + e.getMessage());
        }
        return BytesOperate.base64EncodeData(encoded);
    }


    /**
     * SM2 加密 使用证书
     *
     * @param cert   证书数据 base64编码
     * @param inData 待加密数据
     * @return 加密后的数据 base64编码的 ASN1 DER编码
     */
    public byte[] sm2EncryptByCertificate(byte[] cert, byte[] inData) throws AFCryptoException {
        //region//======>参数检查 日志打印
        logger.info("使用证书进行SM2加密");
        if (cert == null || cert.length == 0) {
            logger.error("SM2证书加密失败,证书数据为空");
            throw new AFCryptoException("SM2证书加密失败,证书数据为空");
        }
        if (inData == null || inData.length == 0) {
            logger.error("SM2证书加密失败,待加密数据为空");
            throw new AFCryptoException("SM2证书加密失败,待加密数据为空");
        }
        if (validateCertificate(cert) != 0) {
            throw new AFCryptoException("验证签名失败 ----> 当前证书验证未通过，不可使用，请更换证书后重试！！！");

        }
        //endregion
        //从证书中解析出公钥
        SM2PublicKey sm2PublicKey = parseSM2PublicKeyFromCert(cert).to512();
        // 加密数据
        byte[] bytes = cmd.sm2Encrypt(-1, sm2PublicKey.encode(), inData);
        // 封装密文
        SM2Cipher sm2Cipher = new SM2Cipher(bytes).to256();
        SM2CipherStructure sm2CipherStructure = new SM2CipherStructure(sm2Cipher);
        byte[] cipher;
        try {
            cipher = sm2CipherStructure.toASN1Primitive().getEncoded("DER");
        } catch (IOException e) {
            logger.error("SM2证书加密失败,DER编码转换异常:{}", e.getMessage());
            throw new AFCryptoException("SM2证书加密失败,DER编码转换异常:" + e.getMessage());
        }
        return BytesOperate.base64EncodeData(cipher);
    }

    /**
     * SM2 解密 内部私钥
     *
     * @param keyIndex 内部密钥索引
     * @param encData  待解密数据 base64编码的 ASN1 DER编码
     * @return 解密后的数据 base64编码
     */
    public byte[] sm2Decrypt(int keyIndex, byte[] encData) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (encData == null || encData.length == 0) {
            logger.error("SM2内部密钥解密失败,待解密数据为空");
            throw new AFCryptoException("SM2内部密钥解密失败,待解密数据为空");
        }
        if (keyIndex < 0) {
            logger.error("SM2内部密钥解密失败,内部密钥索引非法");
            throw new AFCryptoException("SM2内部密钥解密失败,内部密钥索引非法");
        }
        logger.info("使用内部密钥进行SM2解密");
        //endregion
//        //获取私钥访问权限
//        cmd.getPrivateAccess(keyIndex, 3);
        //密文转换为SM2Cipher
        SM2Cipher sm2Cipher = getSm2Cipher(encData).to512();
        logger.error("SM2内部密钥解密,密文数据:{}", sm2Cipher.encode());
        //SM2解密
        byte[] bytes = cmd.sm2Decrypt(keyIndex, null, sm2Cipher.encode());
        return BytesOperate.base64EncodeData(bytes);
    }

    /**
     * SM2 解密 外部私钥
     *
     * @param privateKey 外部私钥 base64编码的 ASN1 DER编码
     * @param encData    待解密数据 base64编码的 ASN1 DER编码
     * @return 解密后的数据 base64编码
     */
    public byte[] sm2Decrypt(byte[] privateKey, byte[] encData) throws AFCryptoException {
        //region//======>参数检查 日志打印
        if (encData == null || encData.length == 0) {
            logger.error("SM2外部密钥解密失败,待解密数据为空");
            throw new AFCryptoException("SM2外部密钥解密失败,待解密数据为空");
        }
        if (privateKey == null || privateKey.length == 0) {
            logger.error("SM2外部密钥解密失败,外部私钥为空");
            throw new AFCryptoException("SM2外部密钥解密失败,外部私钥为空");
        }
        logger.info("使用外部密钥进行SM2解密");
        //endregion
        //密文转换为SM2Cipher
        SM2Cipher sm2Cipher = getSm2Cipher(encData).to512();
        //解析私钥
        SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(privateKey).to512();
        //SM2解密
        byte[] bytes = cmd.sm2Decrypt(-1, sm2PrivateKey.encode(), sm2Cipher.encode());
        return BytesOperate.base64EncodeData(bytes);
    }


    //endregion

    //region 对称加密

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
            System.gc();
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
    //endregion

    //region对称解密

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
            System.gc();
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
    //endregion

    //region 批量加密

    /**
     * SM4 内部批量加密 ECB
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
                .map(AFSVDevice::padding)
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
    public List<byte[]> sm4ExternalBatchEncryptECB(byte[] key, List<byte[]> plainList) throws AFCryptoException {
        //参数检查
        if (key == null || key.length == 0) {
            logger.error("SM4 批量加密，索引不能为空");
            throw new AFCryptoException("SM4 批量加密，索引不能为空");
        }
        if (plainList == null || plainList.isEmpty()) {
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
        //padding
        plainList = plainList.stream()
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SMS4_ECB, 0, 0, key, null, plainList);
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
     * SM4 密钥句柄批量加密 ECB
     */
    public List<byte[]> sm4HandleBatchEncryptECB(int keyHandle, List<byte[]> plainList) throws AFCryptoException {
        //参数检查

        if (plainList == null || plainList.isEmpty()) {
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
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SMS4_ECB, 2, keyHandle, null, null, plainList);
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
     * SM4 内部批量加密 CBC
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
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SMS4_CBC, 1, keyIndex, null, iv, plainList);
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
     * SM4 外部批量加密 CBC
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
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SMS4_CBC, 0, 0, key, iv, plainList);
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
     * SM4 密钥句柄批量加密 CBC
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
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SMS4_CBC, 2, keyHandle, null, iv, plainList);
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
     * SM1 内部批量加密 ECB
     */
    public List<byte[]> sm1InternalBatchEncryptECB(int keyIndex, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (keyIndex < 0) {
            logger.error("SM1 批量加密，索引不能小于0,当前索引：{}", keyIndex);
            throw new AFCryptoException("SM1 批量加密，索引不能小于0,当前索引：" + keyIndex);
        }
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM1 批量加密，加密数据不能为空");
            throw new AFCryptoException("SM1 批量加密，加密数据不能为空");
        }
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        cipherList = cipherList.stream()
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
        //批量加密
        byte[] bytes = cmd.symEncryptBatch(Algorithm.SGD_SM1_ECB, 1, keyIndex, null, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM1 批量加密，加密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM1 批量加密，加密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        //循环读取放入list
        return IntStream.range(0, count)
                .mapToObj(i -> buf.readOneData())
                .collect(Collectors.toList());
    }

    /**
     * SM1 外部批量加密 ECB
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
        //list 总长度<2M
        int totalLength = plainList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);

        }
        //padding
        plainList = plainList.stream()
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
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
        return IntStream.range(0, count)
                .mapToObj(i -> buf.readOneData())
                .collect(Collectors.toList());
    }

    /**
     * SM1 密钥句柄批量加密 ECB
     */
    public List<byte[]> sm1HandleBatchEncryptECB(int keyHandle, List<byte[]> plainList) throws AFCryptoException {
        //参数检查

        if (plainList == null || plainList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }
        //list 总长度<2M
        int totalLength = plainList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }

        //padding
        plainList = plainList.stream()
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
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
        return IntStream.range(0, count)
                .mapToObj(i -> buf.readOneData())
                .collect(Collectors.toList());
    }

    /**
     * SM1 内部密钥批量加密 CBC
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
        //list 总长度<2M
        int totalLength = plainList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream()
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
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
        return IntStream.range(0, count)
                .mapToObj(i -> buf.readOneData())
                .collect(Collectors.toList());
    }

    /**
     * SM1 外部密钥批量加密 CBC
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
        //list 总长度<2M
        int totalLength = plainList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream()
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
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
        return IntStream.range(0, count)
                .mapToObj(i -> buf.readOneData())
                .collect(Collectors.toList());
    }

    /**
     * SM1 密钥句柄批量加密 CBC
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
        //list 总长度<2M
        int totalLength = plainList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM1 批量加密，加密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM1 批量加密，加密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //padding
        plainList = plainList.stream()
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
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
        return IntStream.range(0, count)
                .mapToObj(i -> buf.readOneData())
                .collect(Collectors.toList());
    }
    //endregion

    //region批量解密

    /**
     * SM4 内部批量解密 ECB
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SMS4_ECB, 1, keyIndex, null, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        return getCollect(buf, count);
    }

    /**
     * SM4 外部批量解密 ECB
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SMS4_ECB, 0, 0, key, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        return getCollect(buf, count);
    }

    /**
     * SM4 密钥句柄批量解密 ECB
     */

    public List<byte[]> sm4HandleBatchDecryptECB(int keyHandle, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查
        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM4 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM4 批量解密，解密数据不能为空");
        }
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SMS4_ECB, 2, keyHandle, null, null, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        return getCollect(buf, count);
    }

    /**
     * SM4 内部批量解密 CBC
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SMS4_CBC, 1, keyIndex, null, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        return getCollect(buf, count);
    }

    /**
     * SM4 外部密钥批量解密 CBC
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SMS4_CBC, 0, 0, key, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        return getCollect(buf, count);
    }

    /**
     * SM4 密钥句柄批量解密 CBC
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
        if (totalLength > 2 * 1024 * 1024) {
            logger.error("SM4 批量解密，解密数据总长度不能超过2M,当前长度：{}", totalLength);
            throw new AFCryptoException("SM4 批量解密，解密数据总长度不能超过2M,当前长度：" + totalLength);
        }
        //批量解密
        byte[] bytes = cmd.symDecryptBatch(Algorithm.SGD_SMS4_CBC, 2, keyHandle, null, iv, cipherList);
        BytesBuffer buf = new BytesBuffer(bytes);
        //个数
        int count = buf.readInt();
        if (count != cipherList.size()) {
            logger.error("SM4 批量解密，解密数据个数不匹配，期望个数：{}，实际个数：{}", cipherList.size(), count);
            throw new AFCryptoException("SM4 批量解密，解密数据个数不匹配，期望个数：" + cipherList.size() + "，实际个数：" + count);
        }
        return getCollect(buf, count);
    }

    /**
     * SM1 内部密钥批量解密 ECB
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
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
        return getCollect(buf, count);
    }

    /**
     * SM1 外部密钥批量解密 ECB
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
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
        return getCollect(buf, count);
    }

    /**
     * SM1 密钥句柄批量解密 ECB
     */
    public List<byte[]> sm1HandleBatchDecryptECB(int keyHandle, List<byte[]> cipherList) throws AFCryptoException {
        //参数检查

        if (cipherList == null || cipherList.isEmpty()) {
            logger.error("SM1 批量解密，解密数据不能为空");
            throw new AFCryptoException("SM1 批量解密，解密数据不能为空");
        }
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
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
        return getCollect(buf, count);
    }

    /**
     * SM1 内部密钥批量解密 CBC
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
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
        return getCollect(buf, count);
    }

    /**
     * SM1 外部密钥批量解密 CBC
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
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
        return getCollect(buf, count);
    }

    /**
     * SM1 密钥句柄批量解密 CBC
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
        //list 总长度<2M
        int totalLength = cipherList.stream()
                .mapToInt(bytes -> bytes.length)
                .sum();
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
        return getCollect(buf, count);
    }
    //endregion

    //region MAC 计算

    /**
     * SM4 计算MAC 内部密钥
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
        //data 不能大于2M

        data = padding(data);
        return cmd.mac(Algorithm.SGD_SMS4_CBC, 1, keyIndex, null, iv, data);
    }

    /**
     * SM4 计算MAC 外部密钥
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
        return cmd.mac(Algorithm.SGD_SMS4_CBC, 0, 0, key, iv, data);
    }

    /**
     * SM4 计算MAC 密钥句柄
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
        return cmd.mac(Algorithm.SGD_SMS4_CBC, 2, keyHandle, null, iv, data);
    }

    /**
     * SM1 计算MAC 内部密钥
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

    //region Hash 计算

    /**
     * Hash init
     */
    public void sm3HashInit() throws AFCryptoException {
        cmd.hashInit(Algorithm.SGD_SM3, null, null);
    }

    /**
     * Hash init 带公钥
     *
     * @param publicKey 公钥  公钥由ASN.1结构先DER编码(标准)然后Base64编码(方便识别对比)
     * @param userId    用户ID
     */
    public void sm3HashInitWithPubKey(byte[] publicKey, byte[] userId) throws AFCryptoException {
        //参数检查
        if (publicKey == null) {
            logger.error("SM3 Hash init(带公钥)，公钥不能为空");
            throw new AFCryptoException("SM3 Hash init(带公钥)，公钥不能为空");
        }
        if (userId == null || userId.length == 0) {
            logger.error("SM3 Hash init(带公钥)，用户ID不能为空");
            throw new AFCryptoException("SM3 Hash init(带公钥)，用户ID不能为空");
        }
        //解析公钥
        SM2PublicKey sm2PublicKey = structureToSM2PubKey(publicKey);
        cmd.hashInit(Algorithm.SGD_SM3, sm2PublicKey.encode(), userId);
    }

    /**
     * Hash update
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
     */
    public byte[] sm3HashFinal() throws AFCryptoException {
        return cmd.hashFinal();
    }


    /**
     * SM3 Hash
     */
    public  byte[] sm3Hash(byte[] data) throws AFCryptoException {
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
     */
    public  byte[] sm3HashWithPubKey(byte[] publicKey, byte[] userId, byte[] data) throws AFCryptoException {
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
        return cmd.hash(publicKey, userId, data);
    }
    //endregion

    //region 获取内部密钥句柄 连接个数

    /**
     * 获取内部对称密钥句柄
     */
    public int getSymKeyHandle(int keyIndex) throws AFCryptoException {
        //region//======>参数检查
        if (keyIndex < 0) {
            logger.error("获取内部对称密钥句柄，密钥索引必须大于等于0");
            throw new AFCryptoException("获取内部对称密钥句柄，密钥索引必须大于等于0");
        }
        //endregion
        return cmd.getSymKeyHandle(keyIndex);
    }

    /**
     * 获取连接个数
     */
    public int getConnectCount() throws AFCryptoException {
        return getConnectCount(client);
    }
    //endregion

    //region 证书管理

    /**
     * 获取证书的个数
     * <p>根据证书别名获取信任证书的个数</p>
     *
     * @param altName ：证书别名
     * @return ：证书的个数
     */

    public int getCertCountByAltName(byte[] altName) throws AFCryptoException {
        logger.info("获取证书的个数");
        return cmd.getCertListByAltName(0x01, 0, altName).getCertCount();
    }

    /**
     * 根据别名获取单个证书
     * <p>根据别名获取单个证书</p>
     *
     * @param altName   ：证书别名
     * @param certIndex ：证书索引号(与函数getCertCountByAltName中获取到的值相匹配)
     * @return ：Base64编码的证书文件
     */

    public byte[] getCertByAltName(byte[] altName, int certIndex) throws AFCryptoException {
        logger.info("根据别名获取单个证书");
        byte[] certData = cmd.getCertListByAltName(0x02, certIndex, altName).getCertData();
        return BytesOperate.base64EncodeData(certData);
    }

    /**
     * 获取所有 CA 证书的别名
     *
     * @return 信任列表别名组合，如： CA001|CA002|CA003
     */

    public CertAltNameTrustList getCertTrustListAltName() throws AFCryptoException {
        return cmd.getCertTrustListAltName();
    }


    /**
     * 验证证书有效性
     *
     * @param cert 证书
     * @return 0：验证成功，其他：验证失败
     */
    public int validateCertificate(byte[] cert) throws AFCryptoException {
        logger.info("验证证书有效性");
        byte[] derCert = BytesOperate.base64DecodeCert(new String(cert));
        return cmd.validateCertificate(derCert);
    }


    /**
     * <p>验证证书是否被吊销</p>
     * <p>验证证书是否被吊销，通过CRL模式获取当前证书的有效性。</p>
     *
     * @param base64Certificate ： 待验证的证书--BASE64编码格式
     * @param crlData           :           待验证证书的CRL文件数据 --BASE64编码格式
     * @return ：返回证书验证结果，true ：当前证书已被吊销, false ：当前证书未被吊销
     * @throws CertificateException ：证书异常
     */

    public boolean isCertificateRevoked(byte[] base64Certificate, byte[] crlData) throws CertificateException, AFCryptoException {
        return cmd.isCertificateRevoked(base64Certificate, crlData);
    }

    /**
     * 获取证书信息
     * <p>获取用户指定的证书信息内容</p>
     *
     * @param base64Certificate ：Base64编码的证书文件
     * @param certInfoType      : 用户待获取的证书内容类型 : 类型定义在类{@link com.af.constant.CertParseInfoType}
     * @return ：用户获取到的证书信息内容
     */

    public byte[] getCertInfo(byte[] base64Certificate, int certInfoType) throws AFCryptoException {
        byte[] derCert = BytesOperate.base64DecodeCert(new String(base64Certificate));
        return cmd.getCertInfo(derCert, certInfoType);
    }

    /**
     * 获取证书扩展信息
     * <p>获取用户指定的证书扩展信息内容</p>
     *
     * @param base64Certificate ：Base64编码的证书文件
     * @param certInfoOid       : 用户待获取的证书内容类型OID值 : OID值定义在类 {@link com.af.constant.CertParseInfoType}
     * @return ：用户获取到的证书信息内容
     */

    public byte[] getCertInfoByOid(byte[] base64Certificate, byte[] certInfoOid) throws AFCryptoException {
        byte[] derCert = BytesOperate.base64DecodeCert(new String(base64Certificate));
        return cmd.getCertInfoByOid(derCert, certInfoOid);
    }

    /**
     * 获取设备证书
     * <p>获取服务器证书</p>
     * <p>读取当前应用的服务器的签名证书，如果有签名证书则得到签名证书，否则得到加密证书</p>
     *
     * @return ：Base64编码的服务器证书
     */

    public byte[] getServerCert() throws AFCryptoException {
        byte[] cert;
        cert = cmd.getServerCertByUsage(ConstantNumber.SGD_SERVER_CERT_SIGN);
        if (null == cert) {
            cert = cmd.getServerCertByUsage(ConstantNumber.SGD_SERVER_CERT_ENC);
            if (null == cert) {
                throw new AFCryptoException("获取服务器证书失败");
            }
        }
        return BytesOperate.base64EncodeCert(cert);
    }

    /**
     * 获取设备证书
     *
     * @param usage 证书用途 1：加密证书 | 2：签名证书
     * @return ：Base64编码的服务器证书
     */
    public byte[] getServerCertByUsage(int usage) throws AFCryptoException {
        byte[] cert;
        cert = cmd.getServerCertByUsage(usage);
        if (null == cert) {
            throw new AFCryptoException("获取服务器证书失败");
        }
        return BytesOperate.base64EncodeCert(cert);
    }

    /**
     * 获取应用实体信息
     * <p>获取应用策略</p>
     * <p>根据策略名称获取应用策略，此应用策略为用户在管理程序中创建。用户获取应用策略后，签名服务器会根据用户设定的策略内容进行相关的服务操作</p>
     *
     * @param policyName ：策略名称
     */

    public AFSvCryptoInstance getInstance(String policyName) throws AFCryptoException {
        return cmd.getInstance(policyName.getBytes());
    }

    //根据证书的 DN 信息获取 CA 证书
    public byte[] getCaCertByDn(byte[] dn) throws AFCryptoException {
        return BytesOperate.base64EncodeCert(cmd.getCaCertByDn(dn));
    }

    /**
     * 获取应用实体 签名证书
     *
     * @param policyName : 实体名称
     * @return : Base64编码的证书
     */

    public byte[] getSignCertByPolicyName(String policyName) throws AFCryptoException {
        return BytesOperate.base64EncodeCert(cmd.getCertByPolicyName(policyName.getBytes(), ConstantNumber.SGD_SERVER_CERT_SIGN));
    }

    /**
     * 获取应用实体 加密证书
     *
     * @param policyName : 实体名称
     * @return : Base64编码的证书
     */
    public byte[] getEncCertByPolicyName(String policyName) throws AFCryptoException {
        return BytesOperate.base64EncodeCert(cmd.getCertByPolicyName(policyName.getBytes(), ConstantNumber.SGD_SERVER_CERT_ENC));
    }


    /**
     * 获取证书的OCSP地址
     *
     * @param base64Certificate : Base64编码的证书
     * @return : OCSP地址
     */
    public byte[] getOcspUrl(byte[] base64Certificate) throws AFCryptoException {
        InputStream inStream = new ByteArrayInputStream(BytesOperate.base64DecodeCert(new String(base64Certificate)));
        ASN1InputStream asn1InputStream;
        ASN1Sequence seq;
        try {
            asn1InputStream = new ASN1InputStream(inStream);
            seq = (ASN1Sequence) asn1InputStream.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            TBSCertificateStructure tbsCert = cert.getTBSCertificate();
            ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier(new String(CertParseInfoType.Authority_Info_Access));
            X509Extensions extensions = tbsCert.getExtensions();
            return extensions.getExtension(asn1ObjectIdentifier).getValue().getEncoded();
        } catch (IOException e) {
            throw new AFCryptoException("获取证书中的OCSP URL 错误" + e.getMessage());
        } catch (NullPointerException e) {
            logger.error("获取证书中的OCSP URL 错误,证书中没有OCSP URL");
            return new byte[0];
        }
    }


    //endregion

    //region 编解码 数字信封 签名数据 摘要数据

    /**
     * PKCS7 签名信息编码 默认不带原文
     *
     * @param priKey            : 私钥  ASN.1 编码 Base64 编码
     * @param base64Certificate : Base64 编码的证书
     * @param data              : 待签名数据
     * @return : 签名编码信息数据（DER 编码）  Base64编码
     */
    public byte[] encodeSignedDataForSM2(byte[] priKey, byte[] base64Certificate, byte[] data) throws AFCryptoException {
        //region ======>参数检查
        if (null == priKey || priKey.length == 0) {
            throw new AFCryptoException("私钥不能为空");
        }
        if (null == base64Certificate || base64Certificate.length == 0) {
            throw new AFCryptoException("证书不能为空");
        }
        if (null == data || data.length == 0) {
            throw new AFCryptoException("待签名数据不能为空");
        }
        //endregion
        //解析私钥
        SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(priKey).to512();
        //获取证书
        byte[] derCert = BytesOperate.base64DecodeCert(new String(base64Certificate));
        //编码签名数据
        byte[] bytes = cmd.encodeSignedDataForSM2(0, sm2PrivateKey, derCert, data);
        return BytesOperate.base64EncodeData(bytes);
    }

    /**
     * PKCS7 签名信息编码
     *
     * @param ifCarryText       是否携带原文 true 携带原文 false 不携带原文
     * @param privateKey        私钥
     * @param signerCertificate 签名证书
     * @param data              原文
     * @return 签名编码信息数据（DER 编码）  Base64编码
     */
    public byte[] encodeSignedDataForSM2(boolean ifCarryText, byte[] privateKey, byte[] signerCertificate, byte[] data) throws AFCryptoException {
        try {
            // 解析私钥
            SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(privateKey).to512();
            // 解码证书
            byte[] derCert = BytesOperate.base64DecodeCert(new String(signerCertificate));
            // 编码签名数据
            int flag = 0;
            if (ifCarryText) {
                flag = 1;
            }
            byte[] bytes = cmd.encodeSignedDataForSM2(flag, sm2PrivateKey, derCert, data);
            return BytesOperate.base64EncodeData(bytes);
        } catch (Exception e) {
            logger.error("编码基于SM2算法的签名数据错误");
            throw new AFCryptoException(e);
        }
    }


    /**
     * PKCS7 签名信息解码
     *
     * @param signedData Base64编码的签名数据
     * @return 签名数据结构体 解码后的数据，包括签名者证书，HASH算法标识，被签名的数据以及签名值
     */
    public AFSM2DecodeSignedData decodeSignedDataForSM2(byte[] signedData) throws AFCryptoException {
        byte[] derSignedData = BytesOperate.base64DecodeData(new String(signedData));
        return cmd.decodeSignedDataForSM2(derSignedData);
    }


    /**
     * PKCS7 签名信息验证
     *
     * @param signedData 签名信息
     * @param rawData    原文
     * @return true 验证成功 false 验证失败
     */
    public boolean verifySignedDataForSM2(byte[] signedData, byte[] rawData) throws AFCryptoException {
        byte[] derSignedData = BytesOperate.base64DecodeData(new String(signedData));
        return cmd.verifySignedDataForSM2(rawData, derSignedData);
    }


    /**
     * PKCS7 带签名信息的数字信封编码
     */
    public byte[] encodeEnvelopedDataForSM2(byte[] priKey, byte[] symKey, byte[] signCert, byte[] encCert, byte[] data) throws AFCryptoException {
        //region ======>参数检查
        if (null == priKey || priKey.length == 0) {
            throw new AFCryptoException("私钥不能为空");
        }
        if (null == symKey || symKey.length == 0) {
            throw new AFCryptoException("对称密钥不能为空");
        }
        if (null == signCert || signCert.length == 0) {
            throw new AFCryptoException("签名证书不能为空");
        }
        if (null == encCert || encCert.length == 0) {
            throw new AFCryptoException("加密证书不能为空");
        }
        if (null == data || data.length == 0) {
            throw new AFCryptoException("待签名数据不能为空");
        }
        //endregion
        //解析私钥
        SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(priKey).to512();
        //获取证书
        byte[] derSignCert = BytesOperate.base64DecodeCert(new String(signCert));
        byte[] derEncCert = BytesOperate.base64DecodeCert(new String(encCert));
        //编码签名数据
        byte[] bytes = cmd.encodeEnvelopedDataForSM2(sm2PrivateKey.encode(), symKey, derSignCert, derEncCert, data);
        return BytesOperate.base64EncodeData(bytes);
    }

    /**
     * PKCS7 带签名信息的数字信封解码
     */
    public AFPkcs7DecodeData decodeEnvelopedDataForSM2(byte[] priKey, byte[] encodeData) throws AFCryptoException {
        //region ======>参数检查
        if (null == priKey || priKey.length == 0) {
            throw new AFCryptoException("私钥不能为空");
        }
        if (null == encodeData || encodeData.length == 0) {
            throw new AFCryptoException("待解码数据不能为空");
        }
        //endregion
        //解析私钥
        SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(priKey).to512();
        //base64解析签名数据
        encodeData = Base64.decode(encodeData);
        //解码签名数据
        byte[] bytes = cmd.decodeEnvelopedDataForSM2(sm2PrivateKey.encode(), encodeData);
        BytesBuffer buf = new BytesBuffer(bytes);
        AFPkcs7DecodeData result = new AFPkcs7DecodeData();
        result.setData(buf.readOneData());
        result.setSignerCertificate(buf.readOneData());
        result.setDigestAlgorithm(buf.readInt());
        return result;
    }
    //endregion

    //region//======>P10 Http 证书请求与导入

    /**
     * 根据密钥索引产生证书请求
     * @param keyIndex 密钥索引
     * @param csrRequest 证书请求信息 {@link CsrRequest}
     * @return CSR文件 Base64编码
     */
    public String getCSRByIndex(int keyIndex, CsrRequest csrRequest) throws AFCryptoException {
        //获取服务器地址
        String ip = "";
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
        String url = "https://" + ip + "/mngapi/asymm/generate";
        //发送请求
        int retry = 3;
        while (true) {
            try {
                String body = HttpUtil.createPost(url)
                        .setConnectionTimeout(5 * 1000)
                        .addHeaders(header)
                        .body(params.toString())
                        .execute()
                        .body();

                JSONObject jsonObject = JSONUtil.parseObj(body);
                logger.info("SV-Dev Response: " + jsonObject.toStringPretty());

                int status = jsonObject.getInt("status");
                if (status == 200) {
                    return jsonObject.getJSONObject("result").getStr("csr");
                } else {
                    if (retry-- > 0) {
                        continue;
                    }
                    throw new AFCryptoException("SV-Dev Error: " + jsonObject.getStr("message"));
                }
            } catch (Exception e) {
                logger.error("SV-Dev Error: " + e.getMessage());
                if (retry-- > 0) {
                    continue;
                }
                throw new AFCryptoException(e);
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
        String ip = "";
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
        String url = "https://" + ip + "/mngapi/asymm/importCert";
        int retry = 3;
        while (true) {
            try {
                String body = HttpUtil.createPost(url)
                        .setConnectionTimeout(5 * 1000)
                        .addHeaders(header)
                        .body(params.toString())
                        .execute()
                        .body();

                JSONObject jsonObject = JSONUtil.parseObj(body);
                logger.info("SV-Dev Response: " + jsonObject.toStringPretty());

                int status = jsonObject.getInt("status");
                if (status == 200) {
                    return;
                } else {
                    if (retry-- > 0) {
                        continue;
                    }
                    throw new AFCryptoException("SV-Dev Error: " + jsonObject.getStr("message"));
                }
            } catch (Exception e) {
                // 处理异常情况
                logger.error("SV-Dev Error: " + e.getMessage());
                if (retry-- > 0) {
                    continue;
                }
                throw new AFCryptoException(e);
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
        // 获取服务器地址
        String ip = "";
        if (client instanceof NettyClientChannels) {
            ip = ((NettyClientChannels) client).getNettyChannelPool().getHost();
        }
        // 设置请求头
        HashMap<String, String> header = new HashMap<>();
        header.put("Content-Type", "application/json");
        // 设置请求参数
        JSONObject params = new JSONObject();
        params.set("keyIndex", keyIndex);
        String url = "https://" + ip + "/mngapi/asymm/getCert";
        // 最大重试次数
        int retry = 3;
        // 发送请求
        while (true) {
            try {
                String body = HttpUtil.createPost(url)
                        .setConnectionTimeout(5 * 1000)
                        .addHeaders(header)
                        .body(params.toString())
                        .execute()
                        .body();

                JSONObject jsonObject = JSONUtil.parseObj(body);
                logger.info("SV-Dev Response: " + jsonObject.toStringPretty());

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
                    throw new AFCryptoException("SV-Dev Error: " + jsonObject.getStr("message"));
                }
            } catch (Exception e) {
                logger.error("SV-Dev Error: " + e.getMessage());
                if (retry-- > 0) {
                    continue;
                }
                throw new AFCryptoException(e);
            }
        }
    }


    /**
     * 删除密钥
     *
     * @param keyIndex 密钥索引
     */
    public void deleteKey(int keyIndex) throws AFCryptoException {

        // 获取服务器地址
        String ip = "";
        if (client instanceof NettyClientChannels) {
            ip = ((NettyClientChannels) client).getNettyChannelPool().getHost();
        }
        // 设置请求头
        HashMap<String, String> header = new HashMap<>();
        header.put("Content-Type", "application/json");
        // 设置请求参数
        JSONObject params = new JSONObject();
        params.set("keyIndex", keyIndex);
        String url = "https://" + ip + "/mngapi/asymm/delete";
        // 发送请求
        int retry = 3;
        while (true) {
            try {
                String body = HttpUtil.createPost(url)
                        .setConnectionTimeout(5 * 1000)
                        .addHeaders(header)
                        .body(params.toString())
                        .execute()
                        .body();

                JSONObject jsonObject = JSONUtil.parseObj(body);
                logger.info("SV-Dev Response: " + jsonObject.toStringPretty());

                int status = jsonObject.getInt("status");
                if (status == 200) {
                    logger.info("SV-Dev,删除密钥成功,密钥索引:{}", keyIndex);
                    return;
                } else {
                    if (retry-- > 0) {
                        continue;
                    }
                    throw new AFCryptoException("SV-Dev Error: " + jsonObject.getStr("message"));
                }
            } catch (Exception e) {
                logger.error("SV-Dev Error: " + e.getMessage());
                if (retry-- > 0) {
                    continue;
                }
                throw new AFCryptoException(e);
            }
        }
    }


    //endregion

    //region 工具方法

    /**
     * 根据RSA密钥索引获取密钥模长
     *
     * @param keyIndex 密钥索引
     * @return 密钥模长
     */
    private int getBitsByKeyIndex(int keyIndex) throws AFCryptoException {
        return new RSAPubKey(cmd.exportPublicKey(keyIndex, Algorithm.SGD_RSA_SIGN)).getBits();
    }


    /**
     * 读取文件并且做SHA-256摘要
     *
     * @param filePath 文件路径
     * @return 摘要结果
     */
    private static byte[] fileReadAndDigest(byte[] filePath) {
        MessageDigest md;
        try {
            byte[] bytes = FileUtil.readBytes(new String(filePath));
            md = MessageDigest.getInstance("SHA-256");
            md.update(bytes);
        } catch (NoSuchAlgorithmException e) {
            logger.error("读取文件并且做SHA-256摘要异常", e);
            throw new RuntimeException(e);
        }
        return md.digest();

    }

    /**
     * SM2 字节流转换为 ASN1 编码的私钥
     *
     * @param sm2PublicKey SM2 字节流
     * @return ASN1 编码的私钥DER
     */
    private static byte[] bytesToASN1SM2PubKey(byte[] sm2PublicKey) throws AFCryptoException {
        SM2PublicKey sm2PublicKey256 = new SM2PublicKey(sm2PublicKey).to256();
        byte[] encodedKey;
        try {
            encodedKey = new SM2PublicKeyStructure(sm2PublicKey256).toASN1Primitive().getEncoded("DER");
        } catch (IOException e) {
            logger.error("SM2公钥DER编码失败", e);
            throw new AFCryptoException("SM2公钥DER编码失败", e);
        }
        return BytesOperate.base64EncodeData(encodedKey);
    }

    /**
     * RSA 字节流转换为 ASN1 编码的公钥
     *
     * @param sequenceBytes RSA 服务端返回的字节流
     * @return Base64编码的  ASN1 DER 结构公钥
     */
    private static byte[] bytesToASN1RSAPubKey(byte[] sequenceBytes) throws AFCryptoException {
        byte[] encoded;
        RSAPubKey rsaPubKey = new RSAPubKey(sequenceBytes);
        RSAPublicKeyStructure rsaPublicKeyStructure = new RSAPublicKeyStructure(rsaPubKey);
        try {
            encoded = rsaPublicKeyStructure.toASN1Primitive().getEncoded("DER");
        } catch (IOException e) {
            throw new AFCryptoException("ASN1编码异常");
        }
        return BytesOperate.base64EncodeData(encoded);
    }


    /**
     * 将 ASN1 signature 转化为 SM2Signature
     *
     * @param signature ASN1 signature
     * @return SM2Signature  512位
     */
    private SM2Signature convertToSM2Signature(byte[] signature) throws AFCryptoException {
        byte[] derSignature = BytesOperate.base64DecodeData(new String(signature));
        SM2Signature sm2Signature = new SM2Signature();
        sm2Signature.setLength(256);
        try (ASN1InputStream ais = new ASN1InputStream(derSignature)) {
            SM2SignStructure structure = SM2SignStructure.getInstance(ais.readObject());
            sm2Signature.setR(BigIntegerUtil.asUnsigned32ByteArray(structure.getR()));
            sm2Signature.setS(BigIntegerUtil.asUnsigned32ByteArray(structure.getS()));
            return sm2Signature.to512();
        } catch (IOException e) {
            // 处理异常
            logger.error("SM2内部密钥验证签名失败,序列化失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * 从证书中获取RSA公钥
     *
     * @param certificate 证书 base64 编码 DER
     * @return RSAPubKey 对象
     */
    private RSAPubKey getRSAPublicKeyFromCertificatePath(byte[] certificate) throws AFCryptoException {
        if (null == certificate || certificate.length == 0) {
            logger.info("证书路径为空");
            throw new AFCryptoException("证书路径为空");
        }
        RSAPubKey rsaPubKey = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate));
            PublicKey publicKey = cert.getPublicKey();
            byte[] derRSAPubKey = new byte[publicKey.getEncoded().length - 24];
            System.arraycopy(publicKey.getEncoded(), 24, derRSAPubKey, 0, publicKey.getEncoded().length - 24);
            rsaPubKey = decodeRSAPublicKey(BytesOperate.base64EncodeData(derRSAPubKey));
        } catch (CertificateException e) {
            logger.error("解析证书失败", e);
        }
        return rsaPubKey;
    }

    /**
     * 从证书中解析出SM2公钥
     *
     * @param base64Certificate 证书
     * @return SM2PublicKey SM2公钥 512位
     */
    private static SM2PublicKey parseSM2PublicKeyFromCert(byte[] base64Certificate) throws AFCryptoException {
        logger.info("SV-从证书(证书需要Base64编码)中解析出SM2公钥(AF结构)");
        //解析证书 从证书中获取公钥
        byte[] derCert = BytesOperate.base64DecodeCert(new String(base64Certificate));
        InputStream input = new ByteArrayInputStream(derCert);
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(input)) {
            ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            X509CertificateStructure cert = new X509CertificateStructure((ASN1Sequence) asn1Primitive);
            ASN1BitString publicKeyData = cert.getSubjectPublicKeyInfo().getPublicKeyData();
            byte[] encodePubkey = publicKeyData.getEncoded();
            SM2PublicKey sm2PublicKey = new SM2PublicKey(256, new byte[32], new byte[32]);
            byte[] sm2Pubkey = new byte[sm2PublicKey.size()];
            System.arraycopy(BytesOperate.int2bytes(256), 0, sm2Pubkey, 0, 4);
            System.arraycopy(encodePubkey, 4, sm2Pubkey, 4, 64);
            sm2PublicKey.decode(sm2Pubkey);
            return sm2PublicKey.to512();
        } catch (IOException e) {
            logger.error("证书解析失败", e);
            throw new AFCryptoException("证书解析失败");
        }
    }

    /**
     * SM2 ASN1结构转换为自定义SM2公钥结构
     *
     * @param publicKey 公钥数据 ASN1结构 Base64编码
     * @return SM2公钥 AF结构
     */
    public static SM2PublicKey structureToSM2PubKey(byte[] publicKey) throws AFCryptoException {
        try {
            byte[] decodeKey = BytesOperate.base64DecodeData(new String(publicKey));
            InputStream inputData = new ByteArrayInputStream(decodeKey);
            ASN1InputStream inputStream = new ASN1InputStream(inputData);
            // 读取私钥数据
            ASN1Primitive obj = inputStream.readObject();
            SM2PublicKeyStructure sm2PublicKeyStructure = new SM2PublicKeyStructure((ASN1Sequence) obj);
            return sm2PublicKeyStructure.toSm2PublicKey().to512();
            //自定义私钥结构
        } catch (IOException e) {
            logger.error("SM2 ASN1结构转换为自定义SM2公钥结构错误");
            throw new AFCryptoException("SM2 ASN1结构转换为自定义SM2公钥结构错误");
        }
    }

    /**
     * SM2 ASN1结构转换为自定义SM2私钥结构 512位
     *
     * @param privateKey ：SM2私钥 ASN1结构 Base64编码
     * @return ：自定义SM2私钥结构
     */
    private static SM2PrivateKey structureToSM2PriKey(byte[] privateKey) throws AFCryptoException {
        try {
            byte[] decodeKey = BytesOperate.base64DecodeData(new String(privateKey));
            InputStream inputData = new ByteArrayInputStream(decodeKey);
            ASN1InputStream inputStream = new ASN1InputStream(inputData);
            // 读取私钥数据
            ASN1Primitive obj = inputStream.readObject();
            SM2PrivateKeyStructure pvkStructure = new SM2PrivateKeyStructure((ASN1Sequence) obj);
            //自定义私钥结构
            return pvkStructure.toSM2PrivateKey().to512();
        } catch (IOException e) {
            logger.error("SM2 ASN1结构转换为自定义SM2私钥结构错误");
            throw new AFCryptoException("SM2 ASN1结构转换为自定义SM2私钥结构错误");
        }
    }


    /**
     * RSA 构建公钥结构
     *
     * @param publicKey 公钥数组 ASN1结构 Base64编码
     * @return RSAPubKey 对象
     */
    private RSAPubKey decodeRSAPublicKey(byte[] publicKey) {
        RSAPubKey rsaPubKey = new RSAPubKey();
        //Base64解码
        byte[] derPubKeyData = BytesOperate.base64DecodeData(new String(publicKey));
        //ASN1解码
        try (ASN1InputStream ais = new ASN1InputStream(derPubKeyData)) {
            ASN1Primitive asn1Primitive = ais.readObject();
            RSAPublicKeyStructure rsaPublicKeyStructure = new RSAPublicKeyStructure((ASN1Sequence) asn1Primitive);
            rsaPubKey = rsaPublicKeyStructure.toRSAPubKey();
        } catch (IOException e) {
            logger.error("解析公钥失败", e);
        }
        return rsaPubKey;
    }


    /**
     * RSA 构建私钥结构
     *
     * @param privateKey 私钥数组 ASN1结构 Base64编码
     * @return RSAPriKey SDK私钥结构
     */
    private RSAPriKey decodeRSAPrivateKey(byte[] privateKey) throws AFCryptoException {
        RSAPriKey rsaPriKey;
        byte[] derPrvKeyData = BytesOperate.base64DecodeData(new String(privateKey));
        try (ASN1InputStream ais = new ASN1InputStream(derPrvKeyData)) {
            ASN1Primitive asn1Primitive = ais.readObject();
            RSAPrivateKeyStructure rsaPrivateKeyStructure = new RSAPrivateKeyStructure((ASN1Sequence) asn1Primitive);
            rsaPriKey = rsaPrivateKeyStructure.toRSAPriKey();
        } catch (IOException e) {
            logger.error("解析RSA私钥异常", e);
            throw new AFCryptoException("解析RSA私钥异常");
        }
        return rsaPriKey;
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


    /**
     * 合并数组
     *
     * @param list 数组集合
     * @return 合并后的数组
     */
    private byte[] mergePackage(List<byte[]> list) {
        byte[] newData = new byte[0];
        for (byte[] bytes : list) {
            newData = ArrayUtil.addAll(newData, bytes);
        }
        return newData;
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
            byte[] bytes = cmd.exportPublicKey(index, Algorithm.SGD_RSA_SIGN);
            bits = new RSAPubKey(bytes).getBits();
        } else if (-1 == index && length != -1) { //外部密钥
            bits = length;
        } else {
            logger.error("RSA签名摘要失败,参数错误,index:{},length:{}", index, length);
            throw new AFCryptoException("RSA签名失败,参数错误,index:" + index + ",length:" + length);
        }
        logger.info("RSA签名 摘要计算 当前模长:{}", bits);
        //摘要算法
        String algorithm;
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
        return IntStream.range(0, count)
                .mapToObj(i -> {
                    try {
                        return cutting(buf.readOneData());
                    } catch (AFCryptoException e) {
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toList());
    }

    /**
     * 根据SM2私钥计算SM2公钥
     *
     * @param priKey SM2私钥 Base64编码的 ASN1 DER格式
     * @return SM2公钥 Base64编码的 ASN1 DER格式
     */
    public byte[] getSM2PubKeyFromPriKey(byte[] priKey) throws AFCryptoException {
        logger.info("根据SM2私钥计算SM2公钥");
//        // 导入BC提供的SM2算法实现
//        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // 解码私钥
        byte[] decodedPrivateKey = BytesOperate.base64DecodeData(new String(priKey));

        try (InputStream inputStream = new ByteArrayInputStream(decodedPrivateKey);
             ASN1InputStream asn1InputStream = new ASN1InputStream(inputStream)) {

            // 读取私钥数据
            ASN1Primitive obj = asn1InputStream.readObject();
            SM2PrivateKeyStructure pvkStructure = new SM2PrivateKeyStructure((ASN1Sequence) obj);

            // 获取SM2曲线参数
            X9ECParameters sm2Params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("sm2p256v1");
            ECDomainParameters domainParameters = new ECDomainParameters(sm2Params.getCurve(), sm2Params.getG(), sm2Params.getN(), sm2Params.getH());

            // 创建私钥参数对象
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(pvkStructure.getKey(), domainParameters);

            // 计算公钥
            ECPoint publicKeyPoint = domainParameters.getG().multiply(privateKeyParameters.getD()).normalize();

            // 获取公钥的x和y坐标
            BigInteger publicKeyX = publicKeyPoint.getAffineXCoord().toBigInteger();
            BigInteger publicKeyY = publicKeyPoint.getAffineYCoord().toBigInteger();

            // 构建SM2公钥结构对象
            SM2PublicKeyStructure sm2PublicKeyStructure = new SM2PublicKeyStructure(publicKeyX, publicKeyY);
            byte[] encoded = sm2PublicKeyStructure.toASN1Primitive().getEncoded("DER");
            return BytesOperate.base64EncodeData(encoded);
        } catch (IOException e) {
            logger.error("根据SM2私钥获取公钥失败", e);
            throw new AFCryptoException(e);
        }
        //endregion
    }

    /**
     * ASN1 cipher 转换为 SM2Cipher
     *
     * @param encData ASN1 DER编码的密文
     * @return SM2Cipher AF结构 512位
     */
    private static SM2Cipher getSm2Cipher(byte[] encData) throws AFCryptoException {
        SM2Cipher sm2Cipher;
        byte[] decodeData = BytesOperate.base64DecodePubKey(new String(encData));
        try (ASN1InputStream ais = new ASN1InputStream(decodeData)) {
            SM2CipherStructure structure = SM2CipherStructure.getInstance(ais.readObject());
            sm2Cipher = structure.toSM2Cipher();
        } catch (IOException e) {
            logger.error("密文DER解码失败", e);
            throw new AFCryptoException("密文DER解码失败", e);
        }
        return sm2Cipher;
    }

    //endregion

}
