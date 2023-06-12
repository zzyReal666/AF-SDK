package com.af.device.impl;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.SM3;
import com.af.constant.Algorithm;
import com.af.constant.CertParseInfoType;
import com.af.constant.ConstantNumber;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.device.DeviceInfo;
import com.af.device.IAFSVDevice;
import com.af.device.cmd.AFSVCmd;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.impl.sm2.SM2Cipher;
import com.af.struct.impl.sm2.SM2Signature;
import com.af.struct.signAndVerify.AFPkcs7DecodeData;
import com.af.struct.signAndVerify.AFSM2DecodeSignedData;
import com.af.struct.signAndVerify.AFSvCryptoInstance;
import com.af.struct.signAndVerify.CertAltNameTrustList;
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
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
    public static AFNettyClient client;
    /**
     * 命令对象
     */
    private final AFSVCmd cmd = new AFSVCmd(client, agKey);


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
     * @param index 私钥索引
     */

    public void getPrivateAccess(int index, int keyType) throws AFCryptoException {
        cmd.getPrivateAccess(index, keyType);
    }
    //endregion

    //region 导出公钥

//    /**
//     * <p>导出RSA公钥</p>
//     * <p>导出密码机内部对应索引和用途的RSA公钥信息</p>
//     *
//     * @param keyIndex ：密码设备内部存储的RSA索引号
//     * @param keyUsage ：密钥用途，0：签名公钥；1：加密公钥
//     * @return : 返回Base64编码的公钥数据
//     */
//
//    public byte[] getRSAPublicKey(int keyIndex, int keyUsage) throws AFCryptoException {
//        if (keyIndex < 0 || keyIndex > 1023) {
//            throw new AFCryptoException("keyIndex范围为1-1023");
//        }
//        if (keyUsage != 0 && keyUsage != 1) {
//            throw new AFCryptoException("keyUsage取值为0或1,0:签名公钥;1:加密公钥");
//        }
//        byte[] encoded;
//        byte[] sequenceBytes = cmd.getRSAPublicKey(keyIndex, keyUsage);
//
//        logger.info("返回数据:" + HexUtil.encodeHexStr(sequenceBytes));
//        encoded = bytesToASN1RSAPubKey(sequenceBytes);
//        return BytesOperate.base64EncodeData(encoded);
//    }

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
        logger.info("返回需要对比的数据:" + HexUtil.encodeHexStr(bytes));
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
        logger.info("返回需要对比的数据:" + HexUtil.encodeHexStr(bytes));
        return bytesToASN1RSAPubKey(bytes);
    }


//    /**
//     * <p>导出SM2公钥</p>
//     * <p>导出密码机内部对应索引和用途的SM2公钥信息</p>
//     *
//     * @param keyIndex ：密码设备内部存储的SM2索引号
//     * @param keyUsage ：密钥用途，0：签名公钥；1：加密公钥
//     * @return : 返回Base64编码的公钥数据
//     */
//
//    public byte[] getSm2PublicKey(int keyIndex, int keyUsage) throws AFCryptoException {
//        byte[] keyBytes;
//
//        if (keyUsage == ConstantNumber.ENC_PUBLIC_KEY) {
//            keyBytes = cmd.getSM2EncPublicKey(keyIndex);
//        } else {
//            keyBytes = cmd.getSM2SignPublicKey(keyIndex);
//        }
//        return bytesToASN1SM2PubKey(keyBytes);
//
//    }


    //endregion

    //region 生成密钥对 RSA SM2

    /**
     * 生成密钥对 SM2
     *
     * @param keyType 密钥类型 0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对
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
        }
        //异常
        else {
            logger.error("密钥类型错误,keyType(0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对)={}", keyType);
            throw new AFCryptoException("密钥类型错误,keyType(0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对)=" + keyType);
        }
        //公钥结构体
        SM2PublicKeyStructure sm2PublicKeyStructure = new SM2PublicKeyStructure(sm2KeyPair.getPubKey());
        //私钥结构体
        SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(sm2KeyPair.getPriKey());

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
        logger.info("SV-RSA签名, keyIndex: {}, inDataLen: {}", keyIndex, null == inData ? 0 : inData.length);
        //参数检查
        if (keyIndex <= 0) {
            logger.error("密钥索引错误,keyIndex={}", keyIndex);
            throw new AFCryptoException("密钥索引错误,keyIndex=" + keyIndex);
        }
        if (inData == null || inData.length == 0) {
            logger.error("待签名数据为空");
            throw new AFCryptoException("待签名数据为空");
        }
        //获取私钥访问权限
        cmd.getPrivateAccess(keyIndex, 4);
        //获取模长
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.SIGN_PUBLIC_KEY);
        int bits = new RSAPubKey(rsaPublicKey).getBits();
        //PKCS1 签名填充
        int maxInDataLen = (bits / 8) - 11;
        if (inData.length > maxInDataLen) {
            logger.error("待签名数据长度超过最大长度(可考虑采用文件签名方式), maxInDataLen: {}, inDataLen: {}", maxInDataLen, inData.length);
            throw new AFCryptoException("待签名数据长度超过最大长度(可考虑采用文件签名方式), maxInDataLen=" + maxInDataLen + ", inDataLen=" + inData.length);
        }
        byte[] signData = AFPkcs1Operate.pkcs1EncryptionPrivate(bits, inData);
        //签名 Base64 编码
        return BytesOperate.base64EncodeData(cmd.rsaPrivateKeyOperation(keyIndex, null, Algorithm.SGD_RSA_SIGN, inData));
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
        return BytesOperate.base64EncodeData(cmd.rsaPrivateKeyOperation(0, rsaPriKey, Algorithm.SGD_RSA_SIGN, inData));
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
     * @param fileName   文件名
     * @return Base64编码的签名数据
     */
    public byte[] rsaSignFile(byte[] privateKey, byte[] fileName) throws AFCryptoException {
        // 参数检查
        if (privateKey == null || privateKey.length == 0) {
            logger.error("外部私钥为空");
            throw new AFCryptoException("外部私钥为空");
        }
        if (fileName == null || fileName.length == 0) {
            logger.error("文件名为空");
            throw new AFCryptoException("文件名为空");
        }
        // 解析私钥
        RSAPriKey rsaPriKey = decodeRSAPrivateKey(privateKey);
        // 读取文件 生成文件摘要 SHA256
        byte[] md5Result = fileReadAndDigest(fileName);
        // RSA签名
        return rsaSignature(rsaPriKey.encode(), md5Result);

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
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.SIGN_PUBLIC_KEY);
        int bits = new RSAPubKey(rsaPublicKey).getBits();
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
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificate(certificatePath);
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
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificate(certificatePath);
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
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.ENC_PUBLIC_KEY);
        RSAPubKey rsaPubKey = new RSAPubKey(rsaPublicKey);
        //RSA加密PKCS1填充
        byte[] encData = AFPkcs1Operate.pkcs1EncryptionPublicKey(rsaPubKey.getBits(), data);
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
        byte[] encData = AFPkcs1Operate.pkcs1EncryptionPublicKey(rsaPubKey.getBits(), data);
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
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificate(certificatePath);
        //RSA加密PKCS1填充
        byte[] encData = AFPkcs1Operate.pkcs1EncryptionPublicKey(rsaPubKey.getBits(), data);
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
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.ENC_PUBLIC_KEY);
        RSAPubKey rsaPubKey = new RSAPubKey(rsaPublicKey);
        //RSA解密PKCS1去填充
        byte[] decData = AFPkcs1Operate.pkcs1DecryptPublicKey(rsaPubKey.getBits(), rsaDecrypt);
        //返回解密数据 Base64编码
        return BytesOperate.base64EncodeData(decData);
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
        //获取模长
        byte[] rsaPublicKey = cmd.getRSAPublicKey(0, ConstantNumber.ENC_PUBLIC_KEY);
        RSAPubKey rsaPubKey = new RSAPubKey(rsaPublicKey);
        //RSA解密PKCS1去填充
        byte[] decData = AFPkcs1Operate.pkcs1DecryptPublicKey(rsaPubKey.getBits(), rsaDecrypt);
        //返回解密数据 Base64编码
        return BytesOperate.base64EncodeData(decData);
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
        logger.info("SV-SM2签名-内部密钥");
        //region//======>参数检查
        if (index <= 0) {
            logger.error("密钥索引错误,index={}", index);
            throw new AFCryptoException("密钥索引错误,index=" + index);
        }
        if (data == null || data.length == 0) {
            logger.error("待签名的数据为空");
            throw new AFCryptoException("待签名的数据为空");
        }
        //endregion
        //SM3杂凑
        byte[] digest = new SM3().digest(data);
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
     *
     * @param privateKey 私钥 ASN1结构 Base64编码
     * @param data       待签名数据
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2Signature(byte[] privateKey, byte[] data) throws AFCryptoException {
        logger.info("SV-SM2签名-外部密钥");
        //region//======>参数检查
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
            data = new SM3().digest(data);
            //SM2签名
            SM2Signature sm2Signature = new SM2Signature(cmd.sm2Sign(-1, encodeKey, data)).to256();
            SM2SignStructure sm2SignStructure = new SM2SignStructure(sm2Signature);                              // 转换为ASN1结构
            return BytesOperate.base64EncodeData(sm2SignStructure.toASN1Primitive().getEncoded("DER"));       // DER编码 base64编码
        } catch (IOException e) {
            logger.error("SM2外部密钥签名失败", e);
            throw new AFCryptoException(e);
        }
    }


    /**
     * SM2 签名 外部证书
     *
     * @param data                  待签名数据
     * @param privateKey            私钥 ASN1结构 Base64编码
     * @param base64CertificatePath 证书路径 证书本身需要Base64编码
     * @return 签名数据 Base64编码 ASN1 DER结构
     */
    public byte[] sm2SignatureByCertificate(byte[] data, byte[] privateKey, byte[] base64CertificatePath) throws AFCryptoException {
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
        if (base64CertificatePath == null || base64CertificatePath.length == 0) {
            logger.error("证书为空");
            throw new AFCryptoException("证书为空");
        }
        //endregion
        //解析私钥
        SM2PrivateKey sm2PrivateKey = structureToSM2PriKey(privateKey).to512();
        //从证书中解析出公钥
        SM2PublicKey sm2PublicKey = parseSM2PublicKeyFromCert(base64CertificatePath);
        //对数据进行SM3杂凑 带公钥方式

        return null;



    }

    /**
     * 从证书中解析出SM2公钥
     * @param base64CertificatePath  证书路径 证书本身需要Base64编码
     * @return SM2PublicKey SM2公钥 512位
     */
    private static SM2PublicKey parseSM2PublicKeyFromCert(byte[] base64CertificatePath) throws AFCryptoException {
        logger.info("SV-从证书(证书需要Base64编码)中解析出SM2公钥(AF结构)");
        //解析证书 从证书中获取公钥
        String certData = BytesOperate.readFileByLine(new String(base64CertificatePath));
        byte[] derCert = BytesOperate.base64DecodeCert(new String(certData.getBytes()));
        InputStream input = new ByteArrayInputStream(derCert);
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(input)) {
            asn1InputStream.readObject();
            Certificate cert = Certificate.getInstance(asn1InputStream.readObject());
            byte[] encoded = cert.getSubjectPublicKeyInfo().getPublicKeyData().getEncoded();
            SM2PublicKeyStructure sm2PublicKeyStructure = new SM2PublicKeyStructure(encoded);
            return sm2PublicKeyStructure.toSm2PublicKey().to512();
        } catch (IOException e) {
            logger.error("证书解析失败", e);
            throw new AFCryptoException("证书解析失败");
        }
    }

    /**
     * <p>SM2文件签名</p>
     * <p>使用签名服务器内部密钥对文件进行 SM2签名运算</p>
     *
     * @param index    ：待签名的签名服务器内部密钥索引
     * @param fileName ：待签名的文件名称
     * @return ： base64编码的签名数据
     */

    public byte[] sm2SignFile(int index, byte[] fileName) throws AFCryptoException {
        logger.info("SV_Device 内部密钥文件签名,index:{},fileName:{}", index, new String(fileName));
        String fileData = BytesOperate.readFileByLine(new String(fileName));
        byte[] bytes = cmd.sm2SignFile(index, fileData.getBytes());
        SM2Signature sm2Signature = new SM2Signature(bytes).to256();
        SM2SignStructure structure = new SM2SignStructure(sm2Signature);
        try {
            byte[] encoded = structure.toASN1Primitive().getEncoded("DER");  // DER编码
            return BytesOperate.base64EncodeData(encoded);                     // base64编码
        } catch (IOException e) {
            logger.error("SM2内部密钥签名失败,结构转换为ASN.1结构错误", e);
            throw new AFCryptoException(e);
        }

    }

    /**
     * <p>SM2文件签名</p>
     * <p>使用外部密钥对文件进行 SM2签名运算</p>
     *
     * @param fileName   ：待签名的文件名称
     * @param privateKey ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                   <p>SM2PrivateKey ::= INTEGER</p>
     * @return ： base64编码的签名数据
     */

    public byte[] sm2SignFile(byte[] fileName, byte[] privateKey) throws AFCryptoException {
        byte[] decodeKey = BytesOperate.base64DecodePrivateKey(new String(privateKey));
        InputStream inputData = new ByteArrayInputStream(decodeKey);
        ASN1InputStream inputStream = new ASN1InputStream(inputData);
        try {
            ASN1Primitive obj = inputStream.readObject();
            SM2PrivateKeyStructure pvkStructure = new SM2PrivateKeyStructure((ASN1Sequence) obj);
            SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(BigIntegerUtil.asUnsigned32ByteArray(pvkStructure.getKey())).to512();
            String fileData = BytesOperate.readFileByLine(new String(fileName));
            byte[] bytes = cmd.sm2SignFile(sm2PrivateKey.encode(), fileData.getBytes());
            SM2Signature sm2Signature = new SM2Signature(bytes).to256();
            SM2SignStructure structure = new SM2SignStructure(sm2Signature);
            return BytesOperate.base64EncodeData(structure.toASN1Primitive().getEncoded("DER"));
        } catch (IOException e) {
            logger.error("SM2外部密钥签名失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>SM2文件签名</p>
     * <p>基于证书的SM2文件签名</p>
     *
     * @param fileName          ：待签名的文件名称
     * @param privateKey        ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                          <p>SM2PrivateKey ::= INTEGER</p>
     * @param base64Certificate : 签名的外部证书---BASE64编码
     * @return ： base64编码的签名数据
     */

    public byte[] sm2SignFileByCertificate(byte[] fileName, byte[] privateKey, byte[] base64Certificate) throws AFCryptoException {
        byte[] decodeKey = BytesOperate.base64DecodePrivateKey(new String(privateKey));
        InputStream inputData = new ByteArrayInputStream(decodeKey);
        ASN1InputStream inputStream = new ASN1InputStream(inputData);
        try {
            // 读取私钥数据
            ASN1Primitive obj = inputStream.readObject();
            SM2PrivateKeyStructure pvkStructure = new SM2PrivateKeyStructure((ASN1Sequence) obj);
            SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(BigIntegerUtil.asUnsigned32ByteArray(pvkStructure.getKey())).to512();
            // 读取文件数据
            String fileData = BytesOperate.readFileByLine(new String(fileName));

            //读取证书数据
            String certData = BytesOperate.readFileByLine(new String(base64Certificate));
            byte[] derCert = BytesOperate.base64DecodeCert(new String(certData.getBytes(StandardCharsets.UTF_8)));
            InputStream input = new ByteArrayInputStream(derCert);
            ASN1InputStream certStream = new ASN1InputStream(input);
            ASN1Primitive certObj = certStream.readObject();
            Certificate cert = Certificate.getInstance(certObj);
            byte[] encodePubKey = cert.getSubjectPublicKeyInfo().getPublicKeyData().getEncoded();
            byte[] sm2PubKey = new byte[4 + 32 + 32];
            System.arraycopy(BytesOperate.int2bytes(256), 0, sm2PubKey, 0, 4);
            System.arraycopy(encodePubKey, 4, sm2PubKey, 4, 64);
            SM2PublicKey sm2PublicKey = new SM2PublicKey(sm2PubKey);

            // 签名
            byte[] bytes = cmd.sm2SignFileByCertificate(fileData.getBytes(StandardCharsets.UTF_8), sm2PrivateKey.encode(), sm2PublicKey.encode());
            SM2Signature sm2Signature = new SM2Signature(bytes).to256();
            SM2SignStructure structure = new SM2SignStructure(sm2Signature);
            return BytesOperate.base64EncodeData(structure.toASN1Primitive().getEncoded("DER"));
        } catch (IOException e) {
            logger.error("基于证书的SM2文件签名失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>SM2内部密钥验证签名</p>
     * <p>使用签名服务器内部密钥进行 SM2验证签名运算</p>
     *
     * @param keyIndex  ：待验证签名的签名服务器内部密钥索引
     * @param data      : 待验证签名的原始数据
     * @param signature : 待验证签名的签名数据---BASE64编码格式, 其结构应满足 GM/T 0009-2012中关于SM2签名数据结构的定义
     *                  <p>SM2Signature ::= {</p>
     *                  <p>R INTEGER, --签名值的第一部分</p>
     *                  <p>S INTEGER --签名值的第二部分</p>
     *                  <p>}</p>
     * @return : true ：验证签名成功，false ：验证签名失败
     */

    public boolean sm2Verify(int keyIndex, byte[] data, byte[] signature) throws AFCryptoException {
        byte[] derSignature = BytesOperate.base64DecodeData(new String(signature));
        byte[] signatureData = new byte[64];
        try (ASN1InputStream ais = new ASN1InputStream(derSignature)) {
            SM2SignStructure structure = SM2SignStructure.getInstance(ais.readObject());
            System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getR()), 0, signatureData, 0, 32);
            System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getS()), 0, signatureData, 32, 32);
            SM2Signature sm2Signature = new SM2Signature();
            sm2Signature.decode(signatureData);
            return cmd.sm2Verify(keyIndex, data, sm2Signature.to512().encode());
        } catch (IOException e) {
            // 处理异常
            logger.error("SM2内部密钥验证签名失败,序列化失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>SM2外部密钥验证签名</p>
     * <p>使用外部密钥进行 SM2验证签名运算</p>
     */
    public boolean sm2VerifyByPublicKey(byte[] publicKey, byte[] data, byte[] signature) throws AFCryptoException {
        byte[] derSignature = BytesOperate.base64DecodeData(new String(signature));
        byte[] signatureData = new byte[64];
        try (ASN1InputStream ais = new ASN1InputStream(derSignature)) {
            SM2SignStructure structure = SM2SignStructure.getInstance(ais.readObject());
            System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getR()), 0, signatureData, 0, 32);
            System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getS()), 0, signatureData, 32, 32);
            SM2Signature sm2Signature = new SM2Signature();
            sm2Signature.decode(signatureData);
            return cmd.SM2VerifyByCertPubKey(data, sm2Signature.to512().encode(), new SM2PublicKey(publicKey));
        } catch (IOException e) {
            // 处理异常
            logger.error("SM2外部密钥验证签名失败,序列化失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>基于证书的SM2验证签名</p>
     * <p>使用外部证书进行 SM2验证签名运算，根据签名服务器内部CA证书，验证证书有效性</p>
     *
     * @param base64Certificate ：待验证签名的外部证书---BASE64编码
     * @param data              : 待验证签名的原始数据
     * @param signature         : 待验证签名的签名数据---BASE64编码格式, 其结构应满足 GM/T 0009-2012中关于SM2签名数据结构的定义
     *                          <p>SM2Signature ::= {</p>
     *                          <p>R INTEGER, --签名值的第一部分</p>
     *                          <p>S INTEGER --签名值的第二部分</p>
     *                          <p>}</p>
     * @return : true ：验证签名成功，false ：验证签名失败
     */

    public boolean sm2VerifyByCertificate(byte[] base64Certificate, byte[] data, byte[] signature) throws AFCryptoException {
        logger.info("基于证书的SM2验证签名(外部密钥验签),用外部证书进行 SM2验证签名运算，根据签名服务器内部CA证书，验证证书有效性");
        if (this.validateCertificate(base64Certificate) != 0) {
            throw new AFCryptoException("验证签名失败 ----> 当前证书验证未通过，不可使用，请更换证书后重试！！！");
        } else {
            //读取签名数据
            byte[] derSignature = BytesOperate.base64DecodeData(new String(signature));
            byte[] signatureData = new byte[64];
            try (ASN1InputStream ais = new ASN1InputStream(derSignature)) {
                SM2SignStructure structure = SM2SignStructure.getInstance(ais.readObject());
                System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getR()), 0, signatureData, 0, 32);
                System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getS()), 0, signatureData, 32, 32);

                SM2Signature sm2Signature = new SM2Signature(signatureData).to512();
                return cmd.sm2VerifyByCertificate(base64Certificate, data, sm2Signature.encode());
            } catch (IOException e) {
                // 处理异常
                logger.error("基于证书的SM2验证签名失败,序列化失败", e);
                throw new AFCryptoException(e);
            }

        }
    }

    /**
     * <p>基于证书的SM2验证签名</p>
     * <p>使用外部证书进行 SM2验证签名运算, 通过CRL文件验证证书有效性</p>
     *
     * @param base64Certificate ： 待验证签名的外部证书---BASE64编码
     * @param crlData           :  待验证证书的CRL文件数据 --BASE64编码格式
     * @param data              :  待验证签名的原始数据
     * @param signature         :  待验证签名的签名数据---BASE64编码格式, 其结构应满足 GM/T 0009-2012中关于SM2签名数据结构的定义
     *                          <p>SM2Signature ::= {</p>
     *                          <p>R INTEGER, --签名值的第一部分</p>
     *                          <p>S INTEGER --签名值的第二部分</p>
     *                          <p>}</p>
     * @return : true ：验证签名成功，false ：验证签名失败
     */

    public boolean sm2VerifyByCertificate(byte[] base64Certificate, byte[] crlData, byte[] data, byte[] signature) throws AFCryptoException, CertificateException {
        logger.info("基于证书的SM2验证签名(外部密钥验签),用外部证书进行 SM2验证签名运算, 通过CRL文件验证证书有效性");
        if (this.isCertificateRevoked(base64Certificate, crlData)) {
            throw new AFCryptoException("验证签名失败 ----> 该证书已经吊销，不可使用，请更换证书后重试！！！！");
        } else {
            //读取签名数据
            byte[] derSignature = BytesOperate.base64DecodeData(new String(signature));
            byte[] signatureData = new byte[64];
            try (ASN1InputStream ais = new ASN1InputStream(derSignature)) {
                SM2SignStructure structure = SM2SignStructure.getInstance(ais.readObject());
                System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getR()), 0, signatureData, 0, 32);
                System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getS()), 0, signatureData, 32, 32);

                SM2Signature sm2Signature = new SM2Signature(signatureData).to512();
                return cmd.sm2VerifyByCertificate(base64Certificate, data, sm2Signature.encode());
            } catch (IOException e) {
                // 处理异常
                logger.error("基于证书的SM2验证签名失败,序列化失败", e);
                throw new AFCryptoException(e);
            }

        }
    }

    /**
     * <p>SM2内部密钥验证文件签名</p>
     * <p>使用签名服务器内部密钥对文件进行 SM2验证签名运算</p>
     *
     * @param keyIndex  ：待验证签名的签名服务器内部密钥索引
     * @param fileName  : 文件名称
     * @param signature : 待验证签名的签名数据---BASE64编码格式, 其结构应满足 GM/T 0009-2012中关于SM2签名数据结构的定义
     *                  <p>SM2Signature ::= {</p>
     *                  <p>R INTEGER, --签名值的第一部分</p>
     *                  <p>S INTEGER --签名值的第二部分</p>
     *                  <p>}</p>
     * @return : true ：验证签名成功，false ：验证签名失败
     */

    public boolean sm2VerifyFile(int keyIndex, byte[] fileName, byte[] signature) throws AFCryptoException {
        logger.info("SV-SM2内部密钥验证文件签名,密钥索引:{},文件名称:{},签名数据:{}", keyIndex, fileName, signature.length);

        String fileData = BytesOperate.readFileByLine(new String(fileName));
        byte[] derSignature = BytesOperate.base64DecodeData(new String(signature));
        byte[] signatureData = new byte[64];
        try (ASN1InputStream ais = new ASN1InputStream(derSignature)) {
            SM2SignStructure structure = SM2SignStructure.getInstance(ais.readObject());

            System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getR()), 0, signatureData, 0, 32);
            System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getS()), 0, signatureData, 32, 32);
            SM2Signature sm2Signature = new SM2Signature(signatureData).to512();

            return cmd.sm2Verify(keyIndex, fileData.getBytes(StandardCharsets.UTF_8), sm2Signature.encode());
        } catch (IOException e) {
            logger.error("SM2内部密钥验证文件签名失败,序列化失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>基于证书的SM2验证文件签名</p>
     * <p>使用外部证书对文件进行SM2验证签名运算，根据签名服务器内部CA证书，验证证书有效性</p>
     *
     * @param base64Certificate ：待验证签名的外部证书---BASE64编码
     * @param fileName          : 文件名称
     * @param signature         : 待验证签名的签名数据---BASE64编码格式, 其结构应满足 GM/T 0009-2012中关于SM2签名数据结构的定义
     *                          <p>SM2Signature ::= {</p>
     *                          <p>R INTEGER, --签名值的第一部分</p>
     *                          <p>S INTEGER --签名值的第二部分</p>
     *                          <p>}</p>
     * @return : true ：验证签名成功，false ：验证签名失败
     */

    public boolean sm2VerifyFileByCertificate(byte[] base64Certificate, byte[] fileName, byte[] signature) throws AFCryptoException {
        logger.info("基于证书的SM2验证文件签名(外部密钥验签),使用外部证书对文件进行SM2验证签名运算，根据签名服务器内部CA证书，验证证书有效性");
        if (this.validateCertificate(base64Certificate) != 0) {
            throw new AFCryptoException("验证签名失败 ----> 当前证书验证未通过，不可使用，请更换证书后重试！！！！");
        } else {
            return verifyByCert(base64Certificate, fileName, signature);
        }

    }

    /**
     * <p>基于证书的SM2验证签名</p>
     * <p>使用外部证书对文件进行SM2验证签名运算, 通过CRL文件验证证书有效性</p>
     *
     * @param base64Certificate ： 待验证签名的外部证书---BASE64编码
     * @param crlData           : 待验证证书的CRL文件数据 --BASE64编码格式
     * @param fileName          : 文件名称
     * @param signature         : 待验证签名的签名数据---BASE64编码格式, 其结构应满足 GM/T 0009-2012中关于SM2签名数据结构的定义
     *                          <p>SM2Signature ::= {</p>
     *                          <p>R INTEGER, --签名值的第一部分</p>
     *                          <p>S INTEGER --签名值的第二部分</p>
     *                          <p>}</p>
     * @return : true ：验证签名成功，false ：验证签名失败
     */

    public boolean sm2VerifyFileByCertificate(byte[] base64Certificate, byte[] crlData, byte[] fileName, byte[] signature) throws AFCryptoException, CertificateException {
        logger.info("基于证书的SM2验证文件签名(外部密钥验签),使用外部证书对文件进行SM2验证签名运算, 通过CRL文件验证证书有效性");
        if (this.isCertificateRevoked(base64Certificate, crlData)) {
            throw new AFCryptoException("验证签名失败 ----> 当前证书验证未通过，不可使用，请更换证书后重试！！！！");
        } else {
            return verifyByCert(base64Certificate, fileName, signature);
        }
    }

    /**
     * SM2 外部证书验证签名
     *
     * @param base64Certificate 证书
     * @param fileName          文件名
     * @param signature         签名
     */
    private boolean verifyByCert(byte[] base64Certificate, byte[] fileName, byte[] signature) throws AFCryptoException {
        String fileData = BytesOperate.readFileByLine(new String(fileName));
        byte[] derSignature = BytesOperate.base64DecodeData(new String(signature));
        byte[] signatureData = new byte[64];
        try (ASN1InputStream ais = new ASN1InputStream(derSignature)) {
            SM2SignStructure structure = SM2SignStructure.getInstance(ais.readObject());
            System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getR()), 0, signatureData, 0, 32);
            System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(structure.getS()), 0, signatureData, 32, 32);

            SM2Signature sm2Signature = new SM2Signature(signatureData).to512();
            return cmd.sm2VerifyByCertificate(base64Certificate, fileData.getBytes(StandardCharsets.UTF_8), sm2Signature.encode());
        } catch (IOException e) {
            logger.error("基于证书的SM2验证文件签名失败,序列化失败", e);
            throw new AFCryptoException(e);
        }
    }


    /**
     * <p>sm2加密</p>
     * <p>使用内部密钥进行SM2加密</p>
     *
     * @param keyIndex ：密码设备内部密钥索引
     * @param inData   ：待加密的数据原文
     * @return ：Base64编码的密文数据
     */

    public byte[] sm2Encrypt(int keyIndex, byte[] inData) throws AFCryptoException {
        SM2Cipher sm2Cipher = new SM2Cipher(cmd.sm2Encrypt(keyIndex, inData)).to256();
        SM2CipherStructure sm2CipherStructure = new SM2CipherStructure(sm2Cipher);
        try {
            byte[] encoded = sm2CipherStructure.toASN1Primitive().getEncoded("DER");
            return BytesOperate.base64EncodeData(encoded);
        } catch (IOException e) {
            logger.error("密文DER编码失败", e);
            throw new AFCryptoException("密文DER编码失败", e);
        }
    }

    /**
     * <p>sm2加密</p>
     * <p>使用外部钥进行SM2加密</p>
     *
     * @param publicKey ：base64编码的SM2公钥数据, 其结构应满足 GM/T 0009-2012中关于SM2公钥结构的数据定义
     *                  <p>SM2PublicKey ::= BIT STRING</p> 其结构为 04||X||Y
     * @param inData    ：待加密的数据原文
     * @return ：Base64编码的密文数据
     */

    public byte[] sm2Encrypt(byte[] publicKey, byte[] inData) throws AFCryptoException {
        logger.info("使用外部公钥进行SM2加密");
        byte[] decodeKey = BytesOperate.base64DecodePubKey(new String(publicKey));
        SM2PublicKeyStructure structure = new SM2PublicKeyStructure(decodeKey);
        SM2PublicKey sm2PublicKey = structure.toSm2PublicKey();
        byte[] bytes = cmd.sm2Encrypt(sm2PublicKey, inData);
        SM2Cipher sm2Cipher = new SM2Cipher(bytes).to256();

        SM2CipherStructure sm2CipherStructure = new SM2CipherStructure(sm2Cipher);
        try {
            byte[] encoded = sm2CipherStructure.toASN1Primitive().getEncoded("DER");
            return BytesOperate.base64EncodeData(encoded);
        } catch (IOException e) {
            logger.error("密文DER编码失败", e);
            throw new AFCryptoException("密文DER编码失败", e);
        }


    }

    /**
     * <p>sm2加密</p>
     * <p>使用SM2证书对数据进行加密</p>
     *
     * @param certificate ：base64编码的SM2证书数据
     * @param inData      ：待加密的数据原文
     * @return ：Base64编码的密文数据
     */

    public byte[] sm2EncryptByCertificate(byte[] certificate, byte[] inData) throws AFCryptoException {
        logger.info("使用证书进行SM2加密");
        if (this.validateCertificate(certificate) != 0) {
            throw new AFCryptoException("验证签名失败 ----> 当前证书验证未通过，不可使用，请更换证书后重试！！！");

        }
        try {
            // 读取证书数据
            byte[] derCert = BytesOperate.base64DecodePubKey(new String(certificate));
            InputStream input = new ByteArrayInputStream(derCert);
            ASN1InputStream aln = new ASN1InputStream(input);
            Certificate cert = Certificate.getInstance(aln.readObject());
            byte[] encoded = cert.getSubjectPublicKeyInfo().getPublicKeyData().getEncoded();

            // 读取公钥数据
            SM2PublicKey publicKey = new SM2PublicKey(256);
            byte[] sm2Pubkey = new byte[publicKey.size()];
            System.arraycopy(BytesOperate.int2bytes(256), 0, sm2Pubkey, 0, 4);
            System.arraycopy(encoded, 4, sm2Pubkey, 4, 64);
            publicKey.decode(sm2Pubkey);

            // 加密数据
            byte[] bytes = cmd.sm2Encrypt(publicKey, inData);

            // 封装密文
            SM2Cipher sm2Cipher = new SM2Cipher(bytes).to256();
            SM2CipherStructure sm2CipherStructure = new SM2CipherStructure(sm2Cipher);
            byte[] cipher = sm2CipherStructure.toASN1Primitive().getEncoded("DER");
            return BytesOperate.base64EncodeData(cipher);
        } catch (IOException e) {
            logger.error("证书解析失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>sm2解密</p>
     * <p>使用内部密钥进行SM2解密</p>
     *
     * @param keyIndex ：密码设备内部密钥索引
     * @param encData  ：Base64编码的加密数据, 其结构应满足 GM/T 0009-2012中关于SM2公钥结构的数据定义
     *                 <p>SM2Cipher ::= SEQUENCE {</p>
     *                 <p>     XCoordinate     INTEGER, --x分量</p>
     *                 <p>     YCoordinate     INTEGER, --y分量</p>
     *                 <p>     HASH            OCTET STRING SIZE(32), --杂凑值</p>
     *                 <p>     CipherText      OCTET STRING, --密文</p>
     *                 <p>}</p>
     * @return ：原文数据
     */

    public byte[] sm2Decrypt(int keyIndex, byte[] encData) throws AFCryptoException {
        logger.info("使用内部密钥进行SM2解密");
        byte[] decodeData = BytesOperate.base64DecodePubKey(new String(encData));
        try (ASN1InputStream ais = new ASN1InputStream(decodeData)) {
            SM2CipherStructure structure = SM2CipherStructure.getInstance(ais.readObject());
            SM2Cipher sm2Cipher = structure.toSM2Cipher();
            byte[] bytes = cmd.sm2Decrypt(keyIndex, sm2Cipher);

            return BytesOperate.base64EncodeData(bytes);
        } catch (IOException e) {
            logger.error("密文DER解码失败", e);
            throw new AFCryptoException("密文DER解码失败", e);
        }
    }

    /**
     * <p>sm2解密</p>
     * <p>使用外部钥进行SM2解密</p>
     *
     * @param privateKey ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                   <p>SM2PrivateKey ::= INTEGER</p>
     * @param encData    ：Base64编码的加密数据, 其结构应满足 GM/T 0009-2012中关于SM2公钥结构的数据定义
     *                   <p>SM2Cipher ::= SEQUENCE {</p>
     *                   <p>     XCoordinate     INTEGER, --x分量</p>
     *                   <p>     YCoordinate     INTEGER, --y分量</p>
     *                   <p>     HASH            OCTET STRING SIZE(32), --杂凑值</p>
     *                   <p>     CipherText      OCTET STRING, --密文</p>
     *                   <p>}</p>
     * @return ：原文数据
     */

    public byte[] sm2Decrypt(byte[] privateKey, byte[] encData) throws AFCryptoException {
        logger.info("使用外部密钥进行SM2解密");
        byte[] decodeData = BytesOperate.base64DecodePubKey(new String(encData));
        try (ASN1InputStream ais = new ASN1InputStream(decodeData)) {

            //读取密文
            SM2CipherStructure structure = SM2CipherStructure.getInstance(ais.readObject());
            SM2Cipher sm2Cipher = structure.toSM2Cipher();

            //读取私钥
            byte[] decodePrivateKey = BytesOperate.base64DecodePubKey(new String(privateKey));
            ASN1InputStream aln = new ASN1InputStream(new ByteArrayInputStream(decodePrivateKey));
            ASN1Sequence seq = (ASN1Sequence) aln.readObject();
            SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(seq);
            SM2PrivateKey sm2PrivateKey = sm2PrivateKeyStructure.toSM2PrivateKey();

            //解密
            byte[] bytes = cmd.sm2Decrypt(sm2PrivateKey, sm2Cipher);
            return BytesOperate.base64EncodeData(bytes);
        } catch (IOException e) {
            logger.error("密文DER解码失败", e);
            throw new AFCryptoException("密文DER解码失败", e);
        }
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
        //padding
        plainList = plainList.stream()
                .map(AFSVDevice::padding)
                .collect(Collectors.toList());
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

    /**
     * SM4 密钥句柄批量加密 ECB
     */
    public List<byte[]> sm4HandleBatchEncryptECB(int keyHandle, List<byte[]> plainList) throws AFCryptoException {
        //参数检查

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
        if (cipherList == null || cipherList.size() == 0) {
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
        if (plainList == null || plainList.size() == 0) {
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

        if (plainList == null || plainList.size() == 0) {
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
        if (plainList == null || plainList.size() == 0) {
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
        if (plainList == null || plainList.size() == 0) {
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
        if (plainList == null || plainList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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

        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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

        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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
        if (cipherList == null || cipherList.size() == 0) {
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
    public byte[] sm3Hash(byte[] userId, byte[] data) throws AFCryptoException {
        //init
        sm3HashInit();
        //update
        sm3HashUpdate(data);
        //doFinal
        return sm3HashFinal();

    }

    /**
     * SM3 Hash 带公钥
     */
    public byte[] sm3HashWithPubKey(SM2PublicKey publicKey, byte[] userId, byte[] data) throws AFCryptoException {
        //init
        sm3HashInitWithPubKey(publicKey, userId);
        //update
        sm3HashUpdate(data);
        //doFinal
        return sm3HashFinal();
    }
    //endregion

    //region 获取内部密钥句柄 连接个数

    /**
     * 获取内部对称密钥句柄
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
     */
    public int getConnectCount() throws AFCryptoException {
        return getConnectCount(client);
    }
    //endregion

    //region 证书管理

    /**
     * <p>获取证书的个数</p>
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
     * <p>根据别名获取单个证书</p>
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
     * <p>验证证书有效性，通过OCSP模式获取当前证书的有效性。 注：选择此方式验证证书有效性，需连接互联网，或者可以访问到待测证书的OCSP服务器</p>
     *
     * @param base64Certificate : 待验证的证书--BASE64编码格式
     * @return ：返回证书验证结果，0为验证通过
     */

    public int validateCertificate(byte[] base64Certificate) throws AFCryptoException {
        byte[] derCert = BytesOperate.base64DecodeCert(new String(base64Certificate));
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
     * <p>获取证书信息</p>
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
     * <p>获取证书扩展信息</p>
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
    public byte[] getEncCertByPolicyName(byte[] policyName) throws AFCryptoException {
        return BytesOperate.base64EncodeCert(cmd.getCertByPolicyName(policyName, ConstantNumber.SGD_SERVER_CERT_ENC));
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
     * @return 签名数据结构体
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

    //region 工具方法

    /**
     * 读取文件并且做SHA-256摘要
     *
     * @param filePath 文件路径
     * @return 摘要结果
     */
    private static byte[] fileReadAndDigest(byte[] filePath) {
        MessageDigest md;
        try {
            String fileData = BytesOperate.readFileByLine(new String(filePath));
            md = MessageDigest.getInstance("SHA-256");
            md.update(fileData.getBytes(StandardCharsets.UTF_8));
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
     * @param sequenceBytes RSA 字节流
     * @return ASN1 编码的公钥DER
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
        return encoded;
    }

    /**
     * 从证书中获取RSA公钥
     *
     * @param certificatePath 证书路径
     * @return RSAPubKey 对象
     */
    private RSAPubKey getRSAPublicKeyFromCertificate(byte[] certificatePath) throws AFCryptoException {
        logger.info("SV-从证书中获取RSA公钥,证书路径:{}", null == certificatePath ? "" : new String(certificatePath));
        if (null == certificatePath || certificatePath.length == 0) {
            logger.info("证书路径为空");
            throw new AFCryptoException("证书路径为空");
        }
        RSAPubKey rsaPubKey = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new String(certificatePath)));
            PublicKey publicKey = cert.getPublicKey();
            byte[] derRSAPubKey = new byte[publicKey.getEncoded().length - 24];
            System.arraycopy(publicKey.getEncoded(), 24, derRSAPubKey, 0, publicKey.getEncoded().length - 24);
            rsaPubKey = decodeRSAPublicKey(BytesOperate.base64EncodeData(derRSAPubKey));
        } catch (CertificateException | FileNotFoundException e) {
            logger.error("解析证书失败", e);
        }
        return rsaPubKey;
    }


    /**
     * SM2 ASN1结构转换为自定义SM2公钥结构
     *
     * @param publicKey 公钥数据 ASN1结构 Base64编码
     * @return SM2公钥 AF结构
     */
    private static SM2PublicKey structureToSM2PubKey(byte[] publicKey) throws AFCryptoException {
        //base64解码
        byte[] decodeKey = BytesOperate.base64DecodeData(new String(publicKey));
        InputStream inputData = new ByteArrayInputStream(decodeKey);
        SM2PublicKey sm2PublicKey;
        try (ASN1InputStream ais = new ASN1InputStream(inputData)) {
            ASN1Primitive asn1Primitive = new ASN1InputStream(inputData).readObject();
            //ASN1 结构
            SM2PublicKeyStructure sm2PublicKeyStructure = new SM2PublicKeyStructure((ASN1Sequence) asn1Primitive);
            //AF结构 补零512位
            sm2PublicKey = sm2PublicKeyStructure.toSm2PublicKey();
            sm2PublicKey = sm2PublicKey.to512();
        } catch (IOException e) {
            logger.error("解析SM2公钥异常", e);
            throw new AFCryptoException("解析SM2公钥异常");
        }
        return sm2PublicKey;
    }

    /**
     * SM2 ASN1结构转换为自定义SM2私钥结构 512位
     *
     * @param privateKey ：SM2私钥 ASN1结构 Base64编码
     * @return ：自定义SM2私钥结构
     */
    private static SM2PrivateKey structureToSM2PriKey(byte[] privateKey) throws AFCryptoException {
        try {
            byte[] decodeKey = BytesOperate.base64DecodePrivateKey(new String(privateKey));
            InputStream inputData = new ByteArrayInputStream(decodeKey);
            ASN1InputStream inputStream = new ASN1InputStream(inputData);
            // 读取私钥数据
            ASN1Primitive obj = inputStream.readObject();
            SM2PrivateKeyStructure pvkStructure = new SM2PrivateKeyStructure((ASN1Sequence) obj);
            //自定义私钥结构
            return new SM2PrivateKey(256, BigIntegerUtil.asUnsigned32ByteArray(pvkStructure.getKey())).to512();
        } catch (IOException e) {
            logger.error("SM2 ASN1结构转换为自定义SM2私钥结构错误");
            throw new AFCryptoException("SM2 ASN1结构转换为自定义SM2私钥结构错误");
        }
    }

//    /**
//     * SM2私钥构建
//     *
//     * @param privateKey 私钥数据 ASN1结构 Base64编码
//     * @return SM2私钥
//     */
//    private byte[] decodeSM2PrivateKey(byte[] privateKey) throws AFCryptoException {
//        byte[] decodeKey = BytesOperate.base64DecodeData(new String(privateKey));
//        InputStream inputData = new ByteArrayInputStream(decodeKey);
//        SM2PrivateKey sm2PrivateKey;
//        try (ASN1InputStream ais = new ASN1InputStream(inputData)) {
//            ASN1Primitive asn1Primitive = new ASN1InputStream(inputData).readObject();
//            SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure((ASN1Sequence) asn1Primitive);
//            sm2PrivateKey = sm2PrivateKeyStructure.toSM2PrivateKey();
//            sm2PrivateKey = sm2PrivateKey.to512();
//        } catch (IOException e) {
//            logger.error("解析SM2私钥异常", e);
//            throw new AFCryptoException("解析SM2私钥异常");
//        }
//        return sm2PrivateKey.encode();
//    }

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
        byte[] pubKeyData = new byte[rsaPubKey.size()];
        try (ASN1InputStream ais = new ASN1InputStream(derPubKeyData)) {
            RSAPublicKey structure = RSAPublicKey.getInstance(ais.readObject());
            int mLen = structure.getModulus().toString().length();
            int bits = 2048;
            if (mLen == 128) {
                bits = 1024;
            }
            System.arraycopy(BytesOperate.int2bytes(bits), 0, pubKeyData, 0, 4);
            if (bits == 1024) {
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getModulus(), structure.getModulus().toString().length()), 0, pubKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN / 2), ConstantNumber.LiteRSARef_MAX_LEN / 2);
            } else {
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getModulus(), structure.getModulus().toString().length()), 0, pubKeyData, 4, ConstantNumber.LiteRSARef_MAX_LEN);
            }
            System.arraycopy(this.RSAKey_e, 0, pubKeyData, 4 + ConstantNumber.LiteRSARef_MAX_LEN, ConstantNumber.LiteRSARef_MAX_LEN);
            rsaPubKey.decode(pubKeyData);
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
        RSAPriKey rsaPriKey = new RSAPriKey();
        byte[] derPrvKeyData = BytesOperate.base64DecodeData(new String(privateKey));
        byte[] prvKeyData = new byte[rsaPriKey.size()];
        try (ASN1InputStream ais = new ASN1InputStream(derPrvKeyData)) {
            RSAPrivateKey structure = RSAPrivateKey.getInstance(ais.readObject());
            int mLen = structure.getModulus().toString().length();
            int bits = 2048;
            if (mLen == 128) {
                bits = 1024;
            }
            System.arraycopy(BytesOperate.int2bytes(bits), 0, prvKeyData, 0, 4);
            if (bits == 1024) {
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getModulus(), structure.getModulus().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN / 2), ConstantNumber.LiteRSARef_MAX_LEN / 2);
                System.arraycopy(this.RSAKey_e, 0, prvKeyData, 4 + ConstantNumber.LiteRSARef_MAX_LEN, ConstantNumber.LiteRSARef_MAX_LEN);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getPrivateExponent(), structure.getPrivateExponent().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 2) + (ConstantNumber.LiteRSARef_MAX_LEN / 2), ConstantNumber.LiteRSARef_MAX_LEN / 2);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getPrime1(), structure.getPrime1().toString().length()), 0, prvKeyData, 4 + ConstantNumber.LiteRSARef_MAX_LEN * 3 + ConstantNumber.LiteRSARef_MAX_PLEN / 2, ConstantNumber.LiteRSARef_MAX_PLEN / 2);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getPrime2(), structure.getPrime2().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 3) + (ConstantNumber.LiteRSARef_MAX_PLEN) + ConstantNumber.LiteRSARef_MAX_PLEN / 2, ConstantNumber.LiteRSARef_MAX_PLEN / 2);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getExponent1(), structure.getExponent1().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 3) + (ConstantNumber.LiteRSARef_MAX_PLEN * 2) + ConstantNumber.LiteRSARef_MAX_PLEN / 2, ConstantNumber.LiteRSARef_MAX_PLEN / 2);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getExponent2(), structure.getExponent2().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 3) + (ConstantNumber.LiteRSARef_MAX_PLEN * 3) + ConstantNumber.LiteRSARef_MAX_PLEN / 2, ConstantNumber.LiteRSARef_MAX_PLEN / 2);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getCoefficient(), structure.getCoefficient().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 3) + (ConstantNumber.LiteRSARef_MAX_PLEN * 4) + ConstantNumber.LiteRSARef_MAX_PLEN / 2, ConstantNumber.LiteRSARef_MAX_PLEN / 2);
            } else {
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getModulus(), structure.getModulus().toString().length()), 0, prvKeyData, 4, ConstantNumber.LiteRSARef_MAX_LEN);
                System.arraycopy(this.RSAKey_e, 0, prvKeyData, 4 + ConstantNumber.LiteRSARef_MAX_LEN, ConstantNumber.LiteRSARef_MAX_LEN);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getPrivateExponent(), structure.getPrivateExponent().toString().length()), 0, prvKeyData, 4 + ConstantNumber.LiteRSARef_MAX_LEN * 2, ConstantNumber.LiteRSARef_MAX_LEN);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getPrime1(), structure.getPrime1().toString().length()), 0, prvKeyData, 4 + ConstantNumber.LiteRSARef_MAX_LEN * 3, ConstantNumber.LiteRSARef_MAX_PLEN);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getPrime2(), structure.getPrime2().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 3) + (ConstantNumber.LiteRSARef_MAX_PLEN), ConstantNumber.LiteRSARef_MAX_PLEN);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getExponent1(), structure.getExponent1().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 3) + (ConstantNumber.LiteRSARef_MAX_PLEN * 2), ConstantNumber.LiteRSARef_MAX_PLEN);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getExponent2(), structure.getExponent2().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 3) + (ConstantNumber.LiteRSARef_MAX_PLEN * 3), ConstantNumber.LiteRSARef_MAX_PLEN);
                System.arraycopy(BigIntegerUtil.asUnsignedNByteArray(structure.getCoefficient(), structure.getCoefficient().toString().length()), 0, prvKeyData, 4 + (ConstantNumber.LiteRSARef_MAX_LEN * 3) + (ConstantNumber.LiteRSARef_MAX_PLEN * 4), ConstantNumber.LiteRSARef_MAX_PLEN);
            }
            rsaPriKey.decode(prvKeyData);
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
