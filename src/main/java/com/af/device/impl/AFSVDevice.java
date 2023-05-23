package com.af.device.impl;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.crypto.struct.impl.sm2.SM2Signature;
import com.af.crypto.struct.signAndVerify.*;
import com.af.device.DeviceInfo;
import com.af.device.IAFSVDevice;
import com.af.device.cmd.AFSVCmd;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.CertificateException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 签名验签服务器 设备实现类
 * @since 2023/5/16 9:12
 */
@Getter
@Setter
public class AFSVDevice implements IAFSVDevice {
    private static final Logger logger = LoggerFactory.getLogger(AFSVDevice.class);

    /**
     * 协商密钥
     */
    private byte[] agKey;
    /**
     * 通信客户端
     */
    private static AFNettyClient client;
    /**
     * 命令对象
     */
    private final AFSVCmd cmd = new AFSVCmd(client, agKey);

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


    //=====================================API=====================================

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * 获取设备信息异常
     */
    @Override
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        logger.info("获取设备信息-签名验签服务器");
        RequestMessage req = new RequestMessage(CMDCode.CMD_DEVICEINFO, null);
        //发送请求
        ResponseMessage resp = client.send(req);
        if (resp.getHeader().getErrorCode() != 0) {
            logger.error("获取设备信息错误,无响应或者响应码错误,错误码{},错误信息{}", resp.getHeader().getErrorCode(), resp.getHeader().getErrorInfo());
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
     * <p>导入CA证书</p>
     * <p>导入CA证书</p>
     *
     * @param caAltName           :           ca证书别名
     * @param base64CaCertificate ： 待导入的CA证书--BASE64编码格式
     * @return ：返回CA证书导入结果，0为导入成功
     */
    @Override
    public int addCaCertificate(byte[] caAltName, byte[] base64CaCertificate) throws AFCryptoException {
        return cmd.addCaCertificate(caAltName, base64CaCertificate);
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
        byte[] encoded ;
        byte[] sequenceBytes = cmd.getRSAPublicKey(keyIndex, keyUsage);
        //解析公钥
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(sequenceBytes)) {
            ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(asn1InputStream.readObject()); //
            RSAPublicKey rsaPublicKey = RSAPublicKey.getInstance(asn1Sequence); //RSA公钥
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rsaPublicKey.getEncoded()); //公钥信息
            encoded = subjectPublicKeyInfo.getEncoded();
        } catch (IOException e) {
            logger.error("获取RSA公钥异常", e);
            throw new AFCryptoException("获取RSA公钥异常");
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return false;
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
        return false;
    }

    /**
     * <p>RSA验证签名</p>
     * <p>使用证书对数据进行验证签名运算</p>
     *
     * @param certificate   ：base64编码的RSA数字证书
     * @param inData        ：原始数据
     * @param signatureData ：Base64编码的签名数据
     * @return : true : 验证成功，false ：验证失败
     */
    @Override
    public boolean rsaVerifyByCertificate(byte[] certificate, byte[] inData, byte[] signatureData) throws AFCryptoException {
        return false;
    }

    /**
     * <p>对文件进行RSA验证签名</p>
     * <p>使用内部密钥对文件签名值进行验证</p>
     *
     * @param keyIndex      ：密码设备内部存储的RSA索引号
     * @param fileName      ：文件名称
     * @param signatureData ：Base64编码的签名数据
     * @return : true : 验证成功，false ：验证失败
     */
    @Override
    public boolean rsaVerifyFile(int keyIndex, byte[] fileName, byte[] signatureData) throws AFCryptoException {
        return false;
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
        return false;
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
        return false;
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return BytesOperate.base64EncodeData(bytes);
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
        return new byte[0];
    }

    /**
     * <p>基于证书的SM2签名</p>
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return false;
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
        return false;
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
    public boolean sm2VerifyByCertificate(byte[] base64Certificate, byte[] crlData, byte[] data, byte[] signature) throws AFCryptoException {
        return false;
    }

    /**
     * <p>SM2内部密钥验证w文件签名</p>
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
        return false;
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
        return false;
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
    public boolean sm2VerifyFileByCertificate(byte[] base64Certificate, byte[] crlData, byte[] fileName, byte[] signature) throws AFCryptoException {
        return false;
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
    }

    /**
     * <p>查询证书信任列表别名</p>
     * <p>查询证书信任列表别名</p>
     *
     * @return 信任列表别名组合，如： CA001|CA002|CA003
     */
    @Override
    public certAltNameTrustList getCertTrustListAltName() throws AFCryptoException {
        return null;
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
        return 0;
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
        return new byte[0];
    }

    /**
     * <p>获取应用策略</p>
     * <p>根据策略名称获取应用策略，此应用策略为用户在管理程序中创建。用户获取应用策略后，签名服务器会根据用户设定的策略内容进行相关的服务操作</p>
     *
     * @param policyName ：策略名称
     */
    @Override
    public void getInstance(byte[] policyName) throws AFCryptoException {

    }

    /**
     * <p>删除用户证书列表</p>
     * <p>根据证书别名删除证书列表</p>
     *
     * @param altName ：证书列表别名
     */
    @Override
    public void deleteCertList(byte[] altName) throws AFCryptoException {

    }

    /**
     * <p>获取服务器证书</p>
     * <p>读取当前应用的服务器的签名证书，如果有签名证书则得到签名证书，否则得到加密证书</p>
     *
     * @return ：Base64编码的服务器证书
     */
    @Override
    public byte[] getServerCert() throws AFCryptoException {
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
    }

    /**
     * <p>获取证书信息</p>
     * <p>获取用户指定的证书信息内容</p>
     *
     * @param base64Certificate ：Base64编码的证书文件
     * @param certInfoType      : 用户待获取的证书内容类型 : 类型定义在类 certParseInfoType 中
     * @return ：用户获取到的证书信息内容
     */
    @Override
    public byte[] getCertInfo(byte[] base64Certificate, int certInfoType) throws AFCryptoException {
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return null;
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
        return false;
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


}
