package com.af.device.impl;

import cn.hutool.core.util.HexUtil;
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
import com.af.struct.signAndVerify.*;
import com.af.struct.signAndVerify.RSA.RSAPublicKeyStructure;
import com.af.struct.signAndVerify.sm2.SM2CipherStructure;
import com.af.struct.signAndVerify.sm2.SM2PrivateKeyStructure;
import com.af.struct.signAndVerify.sm2.SM2PublicKeyStructure;
import com.af.struct.signAndVerify.sm2.SM2SignStructure;
import com.af.utils.BigIntegerUtil;
import com.af.utils.BytesOperate;
import com.af.utils.pkcs.AFPkcs1Operate;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificate;
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
import java.util.Arrays;
import java.util.List;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 签名验签服务器 设备实现类
 * @since 2023/5/16 9:12
 */
@Getter
@Setter
@ToString
public class AFSVDevice implements IAFSVDevice {
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


    //=====================================API=====================================


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
    @Override
    public void getPrivateAccess(int index, int keyType) throws AFCryptoException {
        cmd.getPrivateAccess(index, keyType);
    }

    /**
     * <p>验证证书有效性</p>
     *
     * <p>验证证书有效性，通过OCSP模式获取当前证书的有效性。 注：选择此方式验证证书有效性，需连接互联网，或者可以访问到待测证书的OCSP服务器</p>
     *
     * @param base64Certificate : 待验证的证书--BASE64编码格式
     * @return ：返回证书验证结果，0为验证通过
     */
    @Override
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
    @Override
    public boolean isCertificateRevoked(byte[] base64Certificate, byte[] crlData) throws CertificateException, AFCryptoException {
        return cmd.isCertificateRevoked(base64Certificate, crlData);
    }


    /**
     * <p>导出RSA公钥</p>
     * <p>导出密码机内部对应索引和用途的RSA公钥信息</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param keyUsage ：密钥用途，0：签名公钥；1：加密公钥
     * @return : 返回Base64编码的公钥数据
     */
    @Override
    public byte[] getRSAPublicKey(int keyIndex, int keyUsage) throws AFCryptoException {
        if (keyIndex < 0 || keyIndex > 1023) {
            throw new AFCryptoException("keyIndex范围为1-1023");
        }
        if (keyUsage != 0 && keyUsage != 1) {
            throw new AFCryptoException("keyUsage取值为0或1,0:签名公钥;1:加密公钥");
        }
        byte[] encoded;
        byte[] sequenceBytes = cmd.getRSAPublicKey(keyIndex, keyUsage);

        logger.info("返回数据:" + HexUtil.encodeHexStr(sequenceBytes));
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
     * <p>RSA签名</p>
     * <p>使用RSA内部密钥进行签名运算</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param inData   ：待签名的原始数据
     * @return : 返回Base64编码的签名数据
     */
    @Override
    public byte[] rsaSignature(int keyIndex, byte[] inData) throws AFCryptoException {
        logger.info("RSA签名, keyIndex: {}, inDataLen: {}", keyIndex, inData.length);

        //获取私钥访问权限
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.SIGN_PUBLIC_KEY);
        RSAPubKey rsaPubKey = new RSAPubKey(rsaPublicKey);
        byte[] signData = AFPkcs1Operate.pkcs1EncryptionPrivate(rsaPubKey.getBits(), inData);
        //签名
        return BytesOperate.base64EncodeData(cmd.rsaSignature(keyIndex, signData));
    }

    /**
     * <p>RSA签名</p>
     * <p>使用RSA外部密钥进行签名运算</p>
     *
     * @param privateKey ：base64编码的RSA私钥数据，其结构应满足PKCS#1中的RSA结构定义
     *                   <p>RSAPrivateKey ::= SEQUENCE {</p>
     *                   <p>    version             Version,</p>
     *                   <p>    modulus             INTEGER, --- n</p>
     *                   <p>    publicExponent      INTEGER, --- e</p>
     *                   <p>    privateExponent     INTEGER, --- d</p>
     *                   <p>    prime1              INTEGER, --- p</p>
     *                   <p>    prime2              INTEGER, --- q</p>
     *                   <p>    exponent1           INTEGER, --- d mod (p-1)</p>
     *                   <p>    exponent2           INTEGER, --- d mod (q-1)</p>
     *                   <p>    coefficient         INTEGER, --- (inverse of q) mod p</p>
     *                   <p>    otherPrimeInfos     OtherPrimeInfos OPTIONAL</p>
     *                   <p>}</p>
     * @param inData     ：待签名的原始数据
     * @return : 返回Base64编码的签名数据
     */
    @Override
    public byte[] rsaSignature(byte[] privateKey, byte[] inData) throws AFCryptoException {
        RSAPriKey rsaPriKey = decodeRSAPrivateKey(privateKey);
        int modulus = rsaPriKey.getBits();
        byte[] bytes = AFPkcs1Operate.pkcs1EncryptionPrivate(modulus, inData);
        return BytesOperate.base64EncodeData(cmd.rsaSignature(rsaPriKey, bytes));
    }

    /**
     * RSA 构建私钥结构
     *
     * @param privateKey 私钥字节数组
     * @return RSAPriKey
     */
    private RSAPriKey decodeRSAPrivateKey(byte[] privateKey) {
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
        }
        return rsaPriKey;
    }


    /**
     * <p>对文件进行RSA签名运算</p>
     * <p>使用RSA内部密钥对文件内容进行签名运算</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param fileName ：待签名的文件名称
     * @return : 返回Base64编码的签名数据
     */
    @Override
    public byte[] rsaSignFile(int keyIndex, byte[] fileName) throws AFCryptoException {
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.SIGN_PUBLIC_KEY);
        RSAPubKey rsaPubKey = new RSAPubKey(rsaPublicKey);
        byte[] md5Result = fileDigest(fileName);
        byte[] signData = AFPkcs1Operate.pkcs1EncryptionPrivate(rsaPubKey.getBits(), md5Result);
        byte[] bytes = cmd.rsaSignature(keyIndex, signData);
        return BytesOperate.base64EncodeData(bytes);
    }

    /**
     * 文件做SHA-256摘要
     */
    private static byte[] fileDigest(byte[] fileName) {
        MessageDigest md = null;
        try {
            String fileData = BytesOperate.readFileByLine(new String(fileName));
            md = MessageDigest.getInstance("SHA-256");
            md.update(fileData.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            logger.error("文件做SHA-256摘要异常", e);
            throw new RuntimeException(e);
        }
        return md.digest();

    }

    /**
     * <p>对文件进行RSA签名运算</p>
     * <p>使用外部RSA密钥对文件内容进行签名运算</p>
     *
     * @param privateKey ：base64编码的RSA私钥数据，其结构应满足PKCS#1中的RSA结构定义
     *                   <p>RSAPrivateKey ::= SEQUENCE {</p>
     *                   <p>    version             Version,</p>
     *                   <p>    modulus             INTEGER, --- n</p>
     *                   <p>    publicExponent      INTEGER, --- e</p>
     *                   <p>    privateExponent     INTEGER, --- d</p>
     *                   <p>    prime1              INTEGER, --- p</p>
     *                   <p>    prime2              INTEGER, --- q</p>
     *                   <p>    exponent1           INTEGER, --- d mod (p-1)</p>
     *                   <p>    exponent2           INTEGER, --- d mod (q-1)</p>
     *                   <p>    coefficient         INTEGER, --- (inverse of q) mod p</p>
     *                   <p>    otherPrimeInfos     OtherPrimeInfos OPTIONAL</p>
     *                   <p>}</p>
     * @param fileName   ：待签名的文件名称
     * @return : 返回Base64编码的签名数据
     */
    @Override
    public byte[] rsaSignFile(byte[] privateKey, byte[] fileName) throws AFCryptoException {
        RSAPriKey rsaPriKey = decodeRSAPrivateKey(privateKey);
        byte[] md5Result = fileDigest(fileName);
        byte[] signData = AFPkcs1Operate.pkcs1EncryptionPrivate(rsaPriKey.getBits(), md5Result);
        byte[] bytes = cmd.rsaSignature(rsaPriKey, signData);
        return BytesOperate.base64EncodeData(bytes);
    }

    /**
     * <p>RSA验证签名</p>
     * <p>使用内部RSA密钥对数据进行验证签名运算</p>
     *
     * @param keyIndex      ：密码设备内部存储的RSA索引号
     * @param inData        ：原始数据
     * @param signatureData ：Base64编码的签名数据
     * @return : true : 验证成功，false ：验证失败
     */
    @Override
    public boolean rsaVerify(int keyIndex, byte[] inData, byte[] signatureData) throws AFCryptoException {
        return cmd.rsaVerify(keyIndex, inData, signatureData);
    }

    /**
     * <p>RSA验证签名</p>
     * <p>使用外部RSA密钥对数据进行验证签名运算</p>
     *
     * @param publicKey     ：base64编码的RSA公钥数据，其结构应满足PKCS#1中的RSA结构定义
     *                      <p>RSAPublicKey ::= SEQUENCE {</p>
     *                      <p>    modulus             INTEGER, --- n</p>
     *                      <p>    publicExponent      INTEGER, --- e</p>
     *                      <p>}</p>
     * @param inData        ：原始数据
     * @param signatureData ：Base64编码的签名数据
     * @return : true : 验证成功，false ：验证失败
     */
    @Override
    public boolean rsaVerify(byte[] publicKey, byte[] inData, byte[] signatureData) throws AFCryptoException {
        RSAPubKey rsaPubKey = decodeRSAPublicKey(publicKey);
        return cmd.rsaVerify(rsaPubKey, inData, signatureData);
    }

    /**
     * 构建 RSAPubKey 对象
     *
     * @param publicKey 公钥数据-字节数组
     * @return RSAPubKey 对象
     */
    private RSAPubKey decodeRSAPublicKey(byte[] publicKey) {
        RSAPubKey rsaPubKey = new RSAPubKey();
        byte[] derPubKeyData = BytesOperate.base64DecodeData(new String(publicKey));
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
     * <p>RSA验证签名</p>
     * <p>使用证书对数据进行验证签名运算</p>
     *
     * @param certificate   ：base64编码的RSA数字证书路径
     * @param inData        ：原始数据
     * @param signatureData ：Base64编码的签名数据
     * @return : true : 验证成功，false ：验证失败
     */
    @Override
    public boolean rsaVerifyByCertificate(byte[] certificate, byte[] inData, byte[] signatureData) throws AFCryptoException {
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificate(certificate);
        return cmd.rsaVerify(rsaPubKey, inData, signatureData);
    }

    /**
     * 从证书中获取公钥
     *
     * @param certificatePath 证书路径
     * @return RSAPubKey 对象
     */
    private RSAPubKey getRSAPublicKeyFromCertificate(byte[] certificatePath) {
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
     * <p>对文件进行RSA验证签名</p>
     *
     * @param keyIndex      ：密码设备内部存储的RSA索引号
     * @param fileName      ：文件名称
     * @param signatureData ：Base64编码的签名数据
     */
    @Override
    public boolean rsaVerifyFile(int keyIndex, byte[] fileName, byte[] signatureData) throws AFCryptoException {
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.SIGN_PUBLIC_KEY);
        RSAPubKey rsaPubKey = new RSAPubKey(rsaPublicKey);

        byte[] md5Result = fileDigest(fileName);
        byte[] signData = AFPkcs1Operate.pkcs1EncryptionPrivate(rsaPubKey.getBits(), md5Result);

        return cmd.rsaVerify(keyIndex, signData, signatureData);
    }

    /**
     * <p>对文件进行RSA验证签名</p>
     * <p>使用外部RSA密钥对文件签名值进行验证</p>
     *
     * @param publicKey     ：base64编码的RSA公钥数据，其结构应满足PKCS#1中的RSA结构定义
     *                      <p>RSAPublicKey ::= SEQUENCE {</p>
     *                      <p>    modulus             INTEGER, --- n</p>
     *                      <p>    publicExponent      INTEGER, --- e</p>
     *                      <p>}</p>
     * @param fileName      ：文件名称
     * @param signatureData ：Base64编码的签名数据
     * @return : true : 验证成功，false ：验证失败
     */
    @Override
    public boolean rsaVerifyFile(byte[] publicKey, byte[] fileName, byte[] signatureData) throws AFCryptoException {
        RSAPubKey rsaPubKey = decodeRSAPublicKey(publicKey);
        byte[] md5Result = fileDigest(fileName);
        byte[] signData = AFPkcs1Operate.pkcs1EncryptionPrivate(rsaPubKey.getBits(), md5Result);
        return cmd.rsaVerify(rsaPubKey, signData, signatureData);
    }

    /**
     * <p>RSA验证签名</p>
     * <p>使用证书对文件签名数据进行验证签名运算</p>
     *
     * @param certificate   ：base64编码的RSA数字证书
     * @param fileName      ：文件名称
     * @param signatureData ：Base64编码的签名数据
     * @return : true : 验证成功，false ：验证失败
     */
    @Override
    public boolean rsaVerifyFileByCertificate(byte[] certificate, byte[] fileName, byte[] signatureData) throws AFCryptoException {
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificate(certificate);

        byte[] md5Result = fileDigest(fileName);
        byte[] signData = AFPkcs1Operate.pkcs1EncryptionPrivate(rsaPubKey.getBits(), md5Result);

        return cmd.rsaVerify(rsaPubKey, signData, signatureData);
    }

    /**
     * <p>RSA加密</p>
     * <p>使用内部密钥进行RSA加密</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param inData   ：待加密的原始数据
     * @return ：Base64编码的加密数据
     */
    @Override
    public byte[] rsaEncrypt(int keyIndex, byte[] inData) throws AFCryptoException {
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.ENC_PUBLIC_KEY);
        RSAPubKey rsaPubKey = new RSAPubKey(rsaPublicKey);

        byte[] encData = AFPkcs1Operate.pkcs1EncryptionPublicKey(rsaPubKey.getBits(), inData);
        byte[] rsaEncrypt = cmd.rsaEncrypt(keyIndex, encData);

        return BytesOperate.base64EncodeData(rsaEncrypt);

    }

    /**
     * <p>RSA加密</p>
     * <p>使用外部密钥进行RSA加密</p>
     *
     * @param publicKey ：base64编码的RSA公钥数据，其结构应满足PKCS#1中的RSA结构定义
     *                  <p>RSAPublicKey ::= SEQUENCE {</p>
     *                  <p>    modulus             INTEGER, --- n</p>
     *                  <p>    publicExponent      INTEGER, --- e</p>
     *                  <p>}</p>
     * @param inData    ：待加密的原始数据
     * @return ：Base64编码的加密数据
     */
    @Override
    public byte[] rsaEncrypt(byte[] publicKey, byte[] inData) throws AFCryptoException {
        RSAPubKey rsaPubKey = decodeRSAPublicKey(publicKey);
        byte[] encData = AFPkcs1Operate.pkcs1EncryptionPublicKey(rsaPubKey.getBits(), inData);
        byte[] rsaEncrypt = cmd.rsaEncrypt(rsaPubKey, encData);
        return BytesOperate.base64EncodeData(rsaEncrypt);
    }

    /**
     * <p>RSA加密</p>
     * <p>使用RSA数字证书对数据进行加密</p>
     *
     * @param certificate ：base64编码的RSA数字证书
     * @param inData      ：待加密的原始数据
     * @return ：Base64编码的加密数据
     */
    @Override
    public byte[] rsaEncryptByCertificate(byte[] certificate, byte[] inData) throws AFCryptoException {
        RSAPubKey rsaPubKey = getRSAPublicKeyFromCertificate(certificate);
        byte[] encData = AFPkcs1Operate.pkcs1EncryptionPublicKey(rsaPubKey.getBits(), inData);
        byte[] rsaEncrypt = cmd.rsaEncrypt(rsaPubKey, encData);
        return BytesOperate.base64EncodeData(rsaEncrypt);
    }

    /**
     * <p>RSA解密</p>
     * <p>使用内部密钥进行RSA解密</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param encData  ：Base64编码的加密数据
     * @return ：原始数据
     */
    @Override
    public byte[] rsaDecrypt(int keyIndex, byte[] encData) throws AFCryptoException {
        byte[] rsaPublicKey = cmd.getRSAPublicKey(keyIndex, ConstantNumber.ENC_PUBLIC_KEY);
        RSAPubKey rsaPubKey = new RSAPubKey(rsaPublicKey);

        byte[] rsaDecrypt = cmd.rsaDecrypt(keyIndex, encData);
        byte[] decData = AFPkcs1Operate.pkcs1DecryptPublicKey(rsaPubKey.getBits(), rsaDecrypt);

        return BytesOperate.base64EncodeData(decData);
    }

    /**
     * <p>RSA解密</p>
     * <p>使用外部密钥进行RSA解密</p>
     *
     * @param privateKey ：base64编码的RSA私钥数据，其结构应满足PKCS#1中的RSA结构定义
     *                   <p>RSAPrivateKey ::= SEQUENCE {</p>
     *                   <p>    version             Version,</p>
     *                   <p>    modulus             INTEGER, --- n</p>
     *                   <p>    publicExponent      INTEGER, --- e</p>
     *                   <p>    privateExponent     INTEGER, --- d</p>
     *                   <p>    prime1              INTEGER, --- p</p>
     *                   <p>    prime2              INTEGER, --- q</p>
     *                   <p>    exponent1           INTEGER, --- d mod (p-1)</p>
     *                   <p>    exponent2           INTEGER, --- d mod (q-1)</p>
     *                   <p>    coefficient         INTEGER, --- (inverse of q) mod p</p>
     *                   <p>    otherPrimeInfos     OtherPrimeInfos OPTIONAL</p>
     *                   <p>}</p>
     * @param encData    ：Base64编码的加密数据
     * @return ：原始数据
     */
    @Override
    public byte[] rsaDecrypt(byte[] privateKey, byte[] encData) throws AFCryptoException {
        RSAPriKey rsaPriKey = decodeRSAPrivateKey(privateKey);
        byte[] rsaDecrypt = cmd.rsaDecrypt(rsaPriKey, encData);
        byte[] decData = AFPkcs1Operate.pkcs1DecryptPublicKey(rsaPriKey.getBits(), rsaDecrypt);
        return BytesOperate.base64EncodeData(decData);
    }

    /**
     * <p>SM2内部密钥签名</p>
     * <p>使用签名服务器内部密钥进行 SM2签名运算</p>
     *
     * @param index ：待签名的签名服务器内部密钥索引
     * @param data  ：待签名的数据
     * @return ： base64编码的签名数据
     */
    @Override
    public byte[] sm2Signature(int index, byte[] data) throws AFCryptoException {
        byte[] bytes = cmd.sm2Signature(index, data);
        SM2Signature sm2Signature = new SM2Signature(bytes).to256();
        SM2SignStructure structure = new SM2SignStructure(sm2Signature);
        try {
            byte[] encoded = structure.toASN1Primitive().getEncoded("DER");  // DER编码
            return BytesOperate.base64EncodeData(encoded);                     // base64编码
        } catch (IOException e) {
            logger.error("SM2内部密钥签名失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>SM2外部密钥签名</p>
     * <p>SM2外部密钥签名</p>
     *
     * @param data       ：待签名的数据
     * @param privateKey ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                   <p>SM2PrivateKey ::= INTEGER</p>
     * @return ： base64编码的签名数据
     */
    @Override
    public byte[] sm2Signature(byte[] data, byte[] privateKey) throws AFCryptoException {
        byte[] decodeKey = BytesOperate.base64DecodePrivateKey(new String(privateKey));
        InputStream inputData = new ByteArrayInputStream(decodeKey);
        ASN1InputStream inputStream = new ASN1InputStream(inputData);
        try {
            // 读取私钥数据
            ASN1Primitive obj = inputStream.readObject();
            SM2PrivateKeyStructure pvkStructure = new SM2PrivateKeyStructure((ASN1Sequence) obj);

            //自定义私钥结构
            SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(256, BigIntegerUtil.asUnsigned32ByteArray(pvkStructure.getKey()));
            byte[] encodeKey = sm2PrivateKey.encode();
            SM2Signature sm2Signature = new SM2Signature(cmd.sm2Signature(data, encodeKey)).to256();
            SM2SignStructure sm2SignStructure = new SM2SignStructure(sm2Signature);                              // 转换为ASN1结构
            return BytesOperate.base64EncodeData(sm2SignStructure.toASN1Primitive().getEncoded("DER"));       // DER编码 base64编码
        } catch (IOException e) {
            logger.error("SM2外部密钥签名失败", e);
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>基于证书的SM2签名</p>
     *
     * @param data              ：待签名的数据
     * @param privateKey        ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                          <p>SM2PrivateKey ::= INTEGER</p>
     * @param base64Certificate : 签名的外部证书---BASE64编码
     * @return ： base64编码的签名数据
     */
    @Override
    public byte[] sm2SignatureByCertificate(byte[] data, byte[] privateKey, byte[] base64Certificate) throws AFCryptoException {
        byte[] decodeKey = BytesOperate.base64DecodePrivateKey(new String(privateKey));
        InputStream inputData = new ByteArrayInputStream(decodeKey);
        ASN1InputStream inputStream = new ASN1InputStream(inputData);
        try {
            ASN1Primitive obj = inputStream.readObject();
            SM2PrivateKeyStructure pvkStructure = new SM2PrivateKeyStructure((ASN1Sequence) obj);
            SM2PrivateKey sm2PrivateKey = new SM2PrivateKey(BigIntegerUtil.asUnsigned32ByteArray(pvkStructure.getKey())).to512();
            SM2Signature sm2Signature = new SM2Signature(cmd.sm2Signature(data, sm2PrivateKey.encode())).to256();
            SM2SignStructure sm2SignStructure = new SM2SignStructure(sm2Signature);
            return BytesOperate.base64EncodeData(sm2SignStructure.toASN1Primitive().getEncoded("DER"));
        } catch (IOException e) {
            logger.error("基于证书的SM2签名失败", e);
            throw new AFCryptoException(e);
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
    @Override
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
    @Override
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
    @Override
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
    @Override
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
    @Override
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
    @Override
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
    @Override
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
    @Override
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
    @Override
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
    @Override
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
    @Override
    public byte[] sm2Encrypt(byte[] publicKey, byte[] inData) throws AFCryptoException {
        logger.info("使用外部公钥进行SM2加密");
        byte[] decodeKey = BytesOperate.base64DecodePubKey(new String(publicKey));
        SM2PublicKeyStructure structure = new SM2PublicKeyStructure(decodeKey);
        SM2PublicKey sm2PublicKey = structure.toSm2PubKey();
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
    @Override
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
    @Override
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
    @Override
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

    /**
     * <p>导出SM2公钥</p>
     * <p>导出密码机内部对应索引和用途的SM2公钥信息</p>
     *
     * @param keyIndex ：密码设备内部存储的SM2索引号
     * @param keyUsage ：密钥用途，0：签名公钥；1：加密公钥
     * @return : 返回Base64编码的公钥数据
     */
    @Override
    public byte[] getSm2PublicKey(int keyIndex, int keyUsage) throws AFCryptoException {
        byte[] keyBytes;
        SM2PublicKey sm2PublicKey = new SM2PublicKey();
        if (keyUsage == ConstantNumber.ENC_PUBLIC_KEY) {
            keyBytes = cmd.getSM2EncPublicKey(keyIndex);
            sm2PublicKey.decode(keyBytes);
        } else {
            keyBytes = cmd.getSM2SignPublicKey(keyIndex);
            sm2PublicKey.decode(keyBytes);
        }
        SM2PublicKey sm2PublicKey256 = sm2PublicKey.to256();
        try {
            byte[] encodedKey = new SM2PublicKeyStructure(sm2PublicKey256).toASN1Primitive().getEncoded("DER");
            return BytesOperate.base64EncodeData(encodedKey);
        } catch (IOException e) {
            logger.error("SM2公钥DER编码失败", e);
            throw new AFCryptoException("SM2公钥DER编码失败", e);
        }
    }

    /**
     * 生成密钥对 SM2
     *
     * @param keyType 密钥类型 0:签名密钥对 1:加密密钥对 2:密钥交换密钥对 3:默认密钥对
     * @param length  模长 {@link ModulusLength} : 256
     */
    @Override
    public SM2KeyPair generateSM2KeyPair(int keyType, ModulusLength length) throws AFCryptoException {
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
    @Override
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


    /**
     * <p>查询证书信任列表别名</p>
     * <p>查询证书信任列表别名</p>
     *
     * @return 信任列表别名组合，如： CA001|CA002|CA003
     */
    @Override
    public CertAltNameTrustList getCertTrustListAltName() throws AFCryptoException {
        return cmd.getCertTrustListAltName();
    }

    /**
     * <p>获取证书的个数</p>
     * <p>根据证书别名获取信任证书的个数</p>
     *
     * @param altName ：证书别名
     * @return ：证书的个数
     */
    @Override
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
    @Override
    public byte[] getCertByAltName(byte[] altName, int certIndex) throws AFCryptoException {
        logger.info("根据别名获取单个证书");
        byte[] certData = cmd.getCertListByAltName(0x02, certIndex, altName).getCertData();
        return BytesOperate.base64EncodeData(certData);
    }

    /**
     * <p>获取应用策略</p>
     * <p>根据策略名称获取应用策略，此应用策略为用户在管理程序中创建。用户获取应用策略后，签名服务器会根据用户设定的策略内容进行相关的服务操作</p>
     *
     * @param policyName ：策略名称
     */
    @Override
    public void getInstance(byte[] policyName) throws AFCryptoException {
        cmd.getInstance(policyName);
    }

//    /**
//     * <p>删除用户证书列表</p>
//     * <p>根据证书别名删除证书列表</p>
//     *
//     * @param altName ：证书列表别名
//     */
//    @Override
//    public void deleteCertList(byte[] altName) throws AFCryptoException {
//        cmd.deleteCertList(altName);
//    }


    /**
     * <p>获取服务器证书</p>
     * <p>读取当前应用的服务器的签名证书，如果有签名证书则得到签名证书，否则得到加密证书</p>
     *
     * @return ：Base64编码的服务器证书
     */
    @Override
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
     * <p>获取服务器证书</p>
     * <p>根据证书用途，获取当前的服务器证书</p>
     *
     * @param usage ：证书用途 1：服务器加密证书，2：服务器签名证书
     * @return ：Base64编码的证书
     */
    @Override
    public byte[] getServerCertByUsage(int usage) throws AFCryptoException {
        return BytesOperate.base64EncodeCert(cmd.getServerCertByUsage(usage));

    }

    /**
     * <p>根据策略名称，获取相应的证书</p>
     * <p>根据策略名称，获取相应的证书</p>
     *
     * @param policyName : 策略名称
     * @param certType   : 证书类型 1：加密证书，2：签名证书
     * @return : Base64编码的证书
     */
    @Override
    public byte[] getCertByPolicyName(byte[] policyName, int certType) throws AFCryptoException {
        return BytesOperate.base64EncodeCert(cmd.getCertByPolicyName(policyName, certType));
    }

    /**
     * <p>获取证书中的OCSP URL地址</p>
     * <p>获取证书中的OCSP URL地址</p>
     *
     * @param base64Certificate ： Base64编码的证书
     * @return ： OCSP URL地址
     */
    @Override
    public byte[] getOcspUrl(byte[] base64Certificate) throws AFCryptoException {
        InputStream inStream = new ByteArrayInputStream(BytesOperate.base64DecodeCert(new String(base64Certificate)));
        ASN1InputStream asn1InputStream;
        try {
            asn1InputStream = new ASN1InputStream(inStream);
            Certificate cert = Certificate.getInstance(asn1InputStream.readObject());
            TBSCertificate tbsCertificate = cert.getTBSCertificate();
            byte[] encoded = tbsCertificate.getExtensions().getExtension(new ASN1ObjectIdentifier(new String(CertParseInfoType.Authority_Info_Access))).getExtnValue().getEncoded();
            String stringUrl = new String(encoded);
            int index = stringUrl.indexOf("http:");
            String outUrl = stringUrl.substring(index);
            return outUrl.getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new AFCryptoException("获取证书中的OCSP URL 错误" + e.getMessage());
        }
    }

    /**
     * <p>获取证书信息</p>
     * <p>获取用户指定的证书信息内容</p>
     *
     * @param base64Certificate ：Base64编码的证书文件
     * @param certInfoType      : 用户待获取的证书内容类型 : 类型定义在类{@link com.af.constant.CertParseInfoType}
     * @return ：用户获取到的证书信息内容
     */
    @Override
    public byte[] getCertInfo(byte[] base64Certificate, int certInfoType) throws AFCryptoException {
        byte[] derCert = BytesOperate.base64DecodeCert(new String(base64Certificate));
        return cmd.getCertInfo(derCert, certInfoType);
    }

    /**
     * <p>获取证书扩展信息</p>
     * <p>获取用户指定的证书扩展信息内容</p>
     *
     * @param base64Certificate ：Base64编码的证书文件
     * @param certInfoOid       : 用户待获取的证书内容类型OID值 : OID值定义在类 certParseInfoType 中
     * @return ：用户获取到的证书信息内容
     */
    @Override
    public byte[] getCertInfoByOid(byte[] base64Certificate, byte[] certInfoOid) throws AFCryptoException {
        byte[] derCert = BytesOperate.base64DecodeCert(new String(base64Certificate));
        return cmd.getCertInfoByOid(derCert, certInfoOid);
    }

    /**
     * <p>编码数字信封</p>
     * <p>编码PKCS7格式的带签名的数字信封数据</p>
     *
     * @param keyIndex          : 签名私钥索引
     * @param signKeyUsage      : 私钥的用途
     * @param signerCertificate : Base64编码的签名者证书
     * @param digestAlgorithms  : HASH算法
     * @param encCertificate    : Base64编码的接收者证书
     * @param symmAlgorithm     : 对称算法参数
     * @param data              : 原始数据
     * @return : Base64编码的数字信封数据
     */
    @Override
    public byte[] encodeDataForPkcs7(int keyIndex, int signKeyUsage, byte[] signerCertificate, int digestAlgorithms, byte[] encCertificate, int symmAlgorithm, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>解码数字信封</p>
     * <p>解码PKCS7格式的带签名的数字信封数据</p>
     *
     * @param keyIndex       ：密钥索引
     * @param decodeKeyUsage : 密钥用途
     * @param encodeData     : Base64编码的pkcs7格式的数字信封数据
     * @return : 解码后的数据，包括原始数据、签名证书、签名值等
     */
    @Override
    public AFPkcs7DecodeData decodeDataForPkcs7(int keyIndex, int decodeKeyUsage, byte[] encodeData) throws AFCryptoException {
        return null;
    }

    /**
     * <p>编码签名数据</p>
     * <p>编码PKCS7格式的签名数据</p>
     *
     * @param keyIndex          ：密钥索引
     * @param signKeyUsage      ：密钥用途
     * @param signerCertificate ：Base64编码的签名者证书
     * @param digestAlgorithms  ：HASH算法
     * @param data              ：待签名的数据
     * @return ：Base64编码的签名数据
     */
    @Override
    public byte[] encodeSignedDataForPkcs7(int keyIndex, int signKeyUsage, byte[] signerCertificate, int digestAlgorithms, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>解码签名数据</p>
     * <p>解码PKCS7格式的签名数据</p>
     *
     * @param encodeData ：Base64编码的pkcs7格式的签名数据
     * @return : 解码后的数据，包括原始数据、签名证书、签名值等
     */
    @Override
    public AFPkcs7DecodeSignedData decodeSignedDataForPkcs7(byte[] encodeData) throws AFCryptoException {
        return null;
    }

    /**
     * <p>编码数字信封</p>
     * <p>编码PKCS7格式的数字信封</p>
     *
     * @param data              ：需要做数字信封的数据
     * @param encodeCertificate ：Base64编码的接收者证书
     * @param symmAlgorithm     ：对称算法参数
     * @return ：Base64编码的数字信封数据
     */
    @Override
    public byte[] encodeEnvelopedDataForPkcs7(byte[] data, byte[] encodeCertificate, int symmAlgorithm) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>解码数字信封</p>
     * <p>解码PKCS7格式的数字信封</p>
     *
     * @param keyIndex       ：密钥索引
     * @param decodeKeyUsage ：密钥用途
     * @param envelopedData  ：Base64编码的数字信封数据
     * @return ：数据原文
     */
    @Override
    public byte[] decodeEnvelopedDataForPkcs7(int keyIndex, int decodeKeyUsage, byte[] envelopedData) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>编码摘要数据</p>
     * <p>编码PKCS7格式的摘要数据</p>
     *
     * @param digestAlgorithm ：杂凑算法标识
     * @param data            ：原文数据
     * @return ：Base64编码的摘要数据
     */
    @Override
    public byte[] encodeDigestDataForPkcs7(int digestAlgorithm, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>解码摘要数据</p>
     * <p>解码PKCS7格式的摘要数据</p>
     *
     * @param digestAlgorithm ：杂凑算法标识
     * @param digestData      ：Base64编码的摘要数据
     * @return ：解码后的数据，包括原文和摘要值
     */
    @Override
    public AFPkcs7DecodeDigestData decodeDigestDataForPkcs7(int digestAlgorithm, byte[] digestData) throws AFCryptoException {
        return null;
    }

    /**
     * <p>编码数字信封</p>
     * <p>编码基于SM2算法的带签名的数字信封数据</p>
     *
     * @param keyIndex          ：密钥索引
     * @param signKeyUsage      : 密钥用途
     * @param signerCertificate ：Base64编码的签名者证书
     * @param digestAlgorithms  ：HASH算法
     * @param encodeCertificate ：Base64编码的接收者证书
     * @param symmAlgorithm     ：对称算法参数
     * @param data              ：原文数据
     * @return ：Base64编码的数字信封数据
     */
    @Override
    public byte[] encodeSignedAndEnvelopedDataForSM2(int keyIndex, int signKeyUsage, byte[] signerCertificate, int digestAlgorithms, byte[] encodeCertificate, int symmAlgorithm, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>解码数字信封</p>
     * <p>解码基于SM2算法的带签名的数字信封数据</p>
     *
     * @param keyIndex               ：密钥索引
     * @param decodeKeyUsage         ：密钥用途
     * @param signedAndEnvelopedData ：Base64编码的数字信封数据，其格式应符合GM/T 0010《SM2密码算法加密签名消息语法规范》中SignedAndEnvelopedData的数据类型定义
     * @return ：解码后的数据，包括原文、签名者证书以及HASH算法标识
     */
    @Override
    public AFSM2DecodeSignedAndEnvelopedData decodeSignedAndEnvelopedDataForSM2(int keyIndex, int decodeKeyUsage, byte[] signedAndEnvelopedData) throws AFCryptoException {
        return null;
    }

    /**
     * <p>编码签名数据</p>
     * <p>编码基于SM2算法的签名数据</p>
     *
     * @param keyType           ：消息签名格式，1：带原文，2：不带原文
     * @param privateKey        ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                          <p>SM2PrivateKey ::= INTEGER</p>
     * @param signerCertificate ：Base64编码的签名者证书
     * @param data              ：需要签名的数据
     * @return ：Base64编码的签名数据
     */
    @Override
    public byte[] encodeSignedDataForSM2(int keyType, byte[] privateKey, byte[] signerCertificate, byte[] data) throws AFCryptoException {

        try {
            // 解码私钥
            byte[] decodeKey = BytesOperate.base64DecodePrivateKey(new String(privateKey));
            InputStream inputData = new ByteArrayInputStream(decodeKey);
            ASN1InputStream inputStream = new ASN1InputStream(inputData);
            ASN1Sequence asn1Encodables = (ASN1Sequence) inputStream.readObject();
            SM2PrivateKeyStructure sm2PrivateKeyStructure = new SM2PrivateKeyStructure(asn1Encodables);
            SM2PrivateKey sm2PrivateKey = sm2PrivateKeyStructure.toSM2PrivateKey();
            // 解码证书
            byte[] derCert = BytesOperate.base64DecodeCert(new String(signerCertificate));
            // 编码签名数据
            byte[] bytes = cmd.encodeSignedDataForSM2(keyType, sm2PrivateKey, derCert, data);
            return BytesOperate.base64EncodeData(bytes);
        } catch (IOException e) {
            logger.error("编码基于SM2算法的签名数据错误");
            throw new AFCryptoException(e);
        }
    }

    /**
     * <p>解码签名数据</p>
     * <p>解码基于SM2算法的签名数据</p>
     *
     * @param signedData ：Base64编码的签名数据，其格式应符合GM/T 0010《SM2密码算法加密签名消息语法规范》中SignedData的数据类型定义
     * @return ：解码后的数据，包括签名者证书，HASH算法标识，被签名的数据以及签名值
     */
    @Override
    public AFSM2DecodeSignedData decodeSignedDataForSM2(byte[] signedData) throws AFCryptoException {
        byte[] derSignedData = BytesOperate.base64DecodeData(new String(signedData));
        return cmd.decodeSignedDataForSM2(derSignedData);
    }

    /**
     * <p>验证签名数据</p>
     * <p>验证基于SM2算法的签名数据</p>
     *
     * @param signedData ：Base64编码的签名数据，其格式应符合GM/T 0010《SM2密码算法加密签名消息语法规范》中SignedData的数据类型定义
     * @param rawData    : 数据原文，若签名消息为patch，则此处为null
     * @return ：验证结果，true：验证通过，false：验证失败
     */
    @Override
    public boolean verifySignedDataForSM2(byte[] signedData, byte[] rawData) throws AFCryptoException {
        byte[] derSignedData = BytesOperate.base64DecodeData(new String(signedData));
        return cmd.verifySignedDataForSM2(rawData, derSignedData);
    }

    /**
     * <p>编码数字信封</p>
     * <p>编码基于SM2算法的数字信封</p>
     *
     * @param data              ：需要做数字信封的数据
     * @param encodeCertificate ：Base64编码的接受者证书
     * @param symmAlgorithm     ：对称算法标识
     * @return ：Base64编码的数字信封数据
     */
    @Override
    public byte[] encodeEnvelopedDataForSM2(byte[] data, byte[] encodeCertificate, int symmAlgorithm) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>解码数字信封</p>
     * <p>解码基于SM2算法的数字信封</p>
     *
     * @param keyIndex       ：密钥索引
     * @param decodeKeyUsage ：密钥用途
     * @param envelopedData  ：Base64编码的数字信封数据，其格式应符合GM/T 0010《SM2密码算法加密签名消息语法规范》中EnvelopedData的数据类型定义
     * @return : 数据原文
     */
    @Override
    public byte[] decodeEnvelopedDataForSM2(int keyIndex, int decodeKeyUsage, byte[] envelopedData) throws AFCryptoException {
        return new byte[0];
    }



    /**
     * 释放密钥信息
     *
     * @param id 4 字节密钥信息 ID
     */
    public void releaseKeyPair(int id) throws AFCryptoException {
        cmd.freeKey(id);
    }

    //批量对称加密 CBC
    public byte[] sym(Algorithm algorithm, int keyIndex, byte[] key, byte[] iv, List<byte[]> dataList) throws AFCryptoException {

        return null;

    }

    //================================私有方法,用于本类中数据处理,结构转换===========================================
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

    private static byte[] cutting(byte[] data) {
        int paddingNumber = (int) data[data.length - 1];
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
