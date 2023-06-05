package com.af.device.cmd;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.constant.ConstantNumber;
import com.af.constant.Algorithm;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.device.AFDeviceFactory;
import com.af.device.DeviceInfo;
import com.af.device.impl.AFHsmDevice;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.impl.sm2.SM2Cipher;
import com.af.struct.signAndVerify.*;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import com.af.utils.SM4Utils;
import lombok.Setter;
import lombok.ToString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Locale;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/19 12:02
 */
@ToString
public class AFSVCmd {

    private static final Logger logger = LoggerFactory.getLogger(AFSVCmd.class);
    private final AFNettyClient client;
    @Setter
    private byte[] agKey;

    public AFSVCmd(AFNettyClient client, byte[] agKey) {
        this.client = client;
        this.agKey = agKey;
    }

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * 获取设备信息异常
     */
    public DeviceInfo getDeviceInfo() throws AFCryptoException {  //success
        logger.info("SV-获取设备信息");
        RequestMessage req = new RequestMessage(CMDCode.CMD_DEVICEINFO, null, agKey);
        //发送请求
        ResponseMessage resp = client.send(req);
        if (resp.getHeader().getErrorCode() != 0) {
            logger.error("获取设备信息错误,无响应或者响应码错误,错误码:{},错误信息:{}", resp.getHeader().getErrorCode(), resp.getHeader().getErrorInfo());
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
    public byte[] getRandom(int length) throws AFCryptoException {  //success
        logger.info("SV-获取随机数, length:{}", length);
        byte[] param = new BytesBuffer().append(length).toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATERANDOM, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取随机数失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取随机数失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p>验证证书一</p>
     *
     * <p>验证证书有效性，通过OCSP模式获取当前证书的有效性。 注：选择此方式验证证书有效性，需连接互联网，或者可以访问到待测证书的OCSP服务器</p>
     *
     * @param base64Certificate : 待验证的证书--BASE64编码格式
     * @return ：返回证书验证结果，0为验证通过
     */
    public int validateCertificate(byte[] base64Certificate) throws AFCryptoException { //success
        logger.info("SV-OCSP验证证书有效性, base64Certificate:{}", base64Certificate);
        byte[] param = new BytesBuffer()
                .append(base64Certificate.length)
                .append(base64Certificate)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_VERIFY_CERT, param, agKey);
        ResponseMessage res = client.send(req);
        if (null == res || res.getHeader().getErrorCode() != 0) {
            logger.error("SV-验证证书有效性失败, 错误码:{}, 错误信息:{}", res != null ? res.getHeader().getErrorCode() : 0, res != null ? res.getHeader().getErrorInfo() : null);
            throw new AFCryptoException("SV-验证证书有效性失败, 错误码:" + (res != null ? res.getHeader().getErrorCode() : 0) + ", 错误信息:" + (res != null ? res.getHeader().getErrorInfo() : null));
        }
        return null == res.getDataBuffer() ? -1 : res.getHeader().getErrorCode();
    }


    /**
     * <p>验证证书是否被吊销</p>
     * <p>验证证书是否被吊销，通过CRL模式获取当前证书的有效性。</p>
     *
     * @param base64Certificate ： 待验证的证书--BASE64编码格式
     * @param crlData           :           待验证证书的CRL文件数据 --BASE64编码格式
     * @return ：返回证书验证结果，true ：当前证书已被吊销, false ：当前证书未被吊销
     */
    public boolean isCertificateRevoked(byte[] base64Certificate, byte[] crlData) throws CertificateException, AFCryptoException { //success
        logger.info("SV-验证证书是否被吊销, base64Certificate:{}, crlData:{}", base64Certificate, crlData);
        ByteArrayInputStream inputCertificate = new ByteArrayInputStream(BytesOperate.base64DecodeCert(new String(base64Certificate)));
        CertificateFactory certCf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Cert = (X509Certificate) certCf.generateCertificate(inputCertificate);
        ByteArrayInputStream inputCrl = new ByteArrayInputStream(BytesOperate.base64DecodeCRL(new String(crlData)));
        CertificateFactory crlCf = CertificateFactory.getInstance("X.509");
        X509CRL x509Crl;
        try {
            x509Crl = (X509CRL) crlCf.generateCRL(inputCrl);
        } catch (CRLException e) {
            logger.error("SV-验证证书是否被吊销失败, 错误信息:{}", e.getMessage());
            throw new AFCryptoException(e.getMessage());
        }
        return x509Crl.isRevoked(x509Cert);

    }

    /**
     * 导出RSA公钥 签名公钥/加密公钥
     * <p>导出RSA公钥</p>
     * <p>导出密码机内部对应索引和用途的RSA公钥信息</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param keyUsage ：密钥用途，0：签名公钥；1：加密公钥
     * @return : 返回Base64编码的公钥数据
     */
    public byte[] getRSAPublicKey(int keyIndex, int keyUsage) throws AFCryptoException { //success
        logger.info("SV-导出RSA公钥, keyIndex:{}, keyUsage:{}", keyIndex, keyUsage);
        //参数校验
        if (keyIndex < 0 || keyIndex > 1023) {
            logger.error("SV-导出RSA公钥失败, keyIndex:{} 超出范围(0-1023)", keyIndex);
            throw new AFCryptoException("SV-导出RSA公钥失败, keyIndex:" + keyIndex + " 超出范围(0-1023)");
        }
        int type;
        int cmdID;
        // 导出签名公钥
        if (ConstantNumber.SIGN_PUBLIC_KEY == keyUsage) {
            type = ConstantNumber.SGD_RSA_SIGN;
            cmdID = CMDCode.CMD_EXPORTSIGNPUBLICKEY_RSA;
        }
        // 导出加密公钥
        else if (ConstantNumber.ENC_PUBLIC_KEY == keyUsage) {
            type = ConstantNumber.SGD_RSA_ENC;
            cmdID = CMDCode.CMD_EXPORTENCPUBLICKEY_RSA;
        }
        //非法参数
        else {
            logger.error("SV-导出RSA公钥失败, keyUsage:{} 不合法(0:签名公钥; 1:加密公钥)", keyUsage);
            throw new AFCryptoException("SV-导出RSA公钥失败, keyUsage:" + keyUsage + " 不合法(0:签名公钥; 1:加密公钥)");
        }
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(type)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(cmdID, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出RSA公钥失败, 错误码:{}, 错误信息:{}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出RSA公钥失败, 错误码:" + responseMessage.getHeader().getErrorCode() + ", 错误信息:" + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * RSA签名 内部私钥
     * <p>RSA签名</p>
     * <p>使用RSA内部密钥进行签名运算</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param inData   ：待签名的原始数据
     * @return : 返回Base64编码的签名数据
     */
    public byte[] rsaSignature(int keyIndex, byte[] inData) throws AFCryptoException {
        logger.info("SV-RSA签名, keyIndex:{}, inDataLen:{}", keyIndex, inData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_RSA_SIGN)
                .append(0)
                .append(0) //私钥长度,因为是内部私钥,所以长度为0
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALPRIVATEKEYOPERATION_RSA, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA签名失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA签名失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();

    }

    /**
     * RSA签名 外部私钥
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
    public byte[] rsaSignature(RSAPriKey privateKey, byte[] inData) throws AFCryptoException {
        logger.info("SV-RSA签名, privateKeyLen:{}, inDataLen:{}", privateKey, inData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(ConstantNumber.SGD_RSA_SIGN)
                .append(0)
                .append(privateKey.size())
                .append(privateKey.encode())
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPRIVATEKEYOPERATION_RSA, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA签名失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA签名失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * RSA验证签名 内部公钥
     * <p>RSA验证签名</p>
     * <p>使用内部RSA密钥对数据进行验证签名运算</p>
     *
     * @param keyIndex      ：密码设备内部存储的RSA索引号
     * @param inData        ：原始数据
     * @param signatureData ：Base64编码的签名数据
     * @return : true : 验证成功，false ：验证失败
     */
    public boolean rsaVerify(int keyIndex, byte[] inData, byte[] signatureData) throws AFCryptoException { //success
        logger.info("SV-RSA验签, keyIndex:{}, inDataLen:{}, signatureDataLen:{}", keyIndex, inData.length, signatureData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_RSA_SIGN)
                .append(0)
                .append(0)  //公钥长度 因为是内部公钥，所以不需要传入 长度为0
                .append(signatureData.length)
                .append(signatureData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALPUBLICKEYOPERATION_RSA, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA验签失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA验签失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return Arrays.equals(res.getDataBuffer().readOneData(), inData);
    }

    /**
     * RSA 验证签名 外部公钥
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
    public boolean rsaVerify(RSAPubKey publicKey, byte[] inData, byte[] signatureData) throws AFCryptoException { //success
        logger.info("SV-RSA验签, publicKey:{}, inDataLen:{}, signatureDataLen:{}", publicKey, inData.length, signatureData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(ConstantNumber.SGD_RSA_SIGN)
                .append(0)
                .append(publicKey.size())
                .append(publicKey.encode())
                .append(signatureData.length)
                .append(signatureData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPUBLICKEYOPERATION_RSA, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA验签失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA验签失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return Arrays.equals(res.getDataBuffer().readOneData(), inData);
    }


    /**
     * RSA加密 内部公钥
     * <p>RSA加密</p>
     * <p>使用内部密钥进行RSA加密</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param inData   ：待加密的原始数据
     * @return ：Base64编码的加密数据
     */
    public byte[] rsaEncrypt(int keyIndex, byte[] inData) throws AFCryptoException { //success
        logger.info("SV-RSA加密, keyIndex:{}, inDataLen:{}", keyIndex, inData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_RSA_ENC)
                .append(0)
                .append(0)  //公钥长度 因为是内部公钥加密 所以公钥长度为0
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALPUBLICKEYOPERATION_RSA, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA加密失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA加密失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * RSA加密 外部公钥
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
    public byte[] rsaEncrypt(RSAPubKey publicKey, byte[] inData) throws AFCryptoException { //success
        logger.info("SV-RSA加密, publicKey:{}, inDataLen:{}", publicKey, inData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(ConstantNumber.SGD_RSA_ENC)
                .append(0)
                .append(publicKey.size())
                .append(publicKey.encode())
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPUBLICKEYOPERATION_RSA, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA加密失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA加密失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * RSA 解密 内部私钥
     * <p>RSA解密</p>
     * <p>使用内部密钥进行RSA解密</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param encData  ：Base64编码的加密数据
     * @return ：原始数据
     */
    public byte[] rsaDecrypt(int keyIndex, byte[] encData) throws AFCryptoException {  //success
        logger.info("SV-RSA解密, keyIndex:{}, encDataLen:{}", keyIndex, encData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_RSA_ENC)
                .append(0)
                .append(0)   //私钥长度 因为是内部密钥，所以长度为0
                .append(encData.length)
                .append(encData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALPRIVATEKEYOPERATION_RSA, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA解密失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA解密失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * RSA 解密 外部私钥
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
    public byte[] rsaDecrypt(RSAPriKey privateKey, byte[] encData) throws AFCryptoException { //success
        logger.info("SV-RSA解密, privateKey:{}, encDataLen:{}", privateKey, encData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(ConstantNumber.SGD_RSA_ENC)
                .append(0)
                .append(privateKey.size())
                .append(privateKey.encode())
                .append(encData.length)
                .append(encData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPRIVATEKEYOPERATION_RSA, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA解密失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA解密失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();


    }

    /**
     * 获取私钥访问权限
     *
     * @param index   索引
     * @param keyType 密钥类型 3:SM2 4:RSA
     */
    public void getPrivateAccess(int index, int keyType) throws AFCryptoException { //success
        logger.info("SV-CMD 获取私钥访问权限, index: {}, keyType: {}", index, keyType);
        String pwd = "12345678";
        byte[] param = new BytesBuffer()
                .append(index)
                .append(keyType)
                .append(pwd.length())
                .append(pwd.getBytes(StandardCharsets.UTF_8))
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GETPRIVATEKEYACCESSRIGHT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取私钥访问权限失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取私钥访问权限失败");
        }

    }

    /**
     * <p>SM2内部密钥签名</p>
     * <p>使用签名服务器内部密钥进行 SM2签名运算</p>
     *
     * @param index ：待签名的签名服务器内部密钥索引
     * @param data  ：待签名的数据
     * @return ： base64编码的签名数据
     */
    public byte[] sm2Signature(int index, byte[] data) throws AFCryptoException {  //success
        logger.info("SV_CMD SM2内部密钥签名, index: {}, dataLen: {}", index, data.length);
        getPrivateAccess(index, 3);
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.sm3Hash(data);
        int begin = 1;
        byte[] param = new BytesBuffer()
                .append(begin)
                .append(index)
                .append(hash.length)
                .append(hash)
                .toBytes();

        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_INTERNALSIGN_ECC, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM2内部密钥签名失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2内部密钥签名失败");
        }
        return responseMessage.getDataBuffer().readOneData();
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
    public byte[] sm2Signature(byte[] data, byte[] privateKey) throws AFCryptoException {   //success
        logger.info("SV-CMD SM2外部密钥签名, data: {}, privateKey: {}", data, privateKey);
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.sm3Hash(data);
        int zero = 0;
        byte[] param = new BytesBuffer()
                .append(zero)
                .append(ConstantNumber.SGD_SM2_1)
                .append(zero)
                .append(privateKey.length)
                .append(privateKey)
                .append(hash.length)
                .append(hash)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALSIGN_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SM2外部密钥签名失败, 错误码: {}, 错误信息: {}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2外部密钥签名失败");
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * SM2验证签名 内部密钥
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
    public boolean sm2Verify(int keyIndex, byte[] data, byte[] signature) throws AFCryptoException {  //success
        logger.info("SV-SM2内部密钥验证签名");
        getPrivateAccess(keyIndex, 3);
        int begin = 1;
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.sm3Hash(data);
        byte[] param = new BytesBuffer()
                .append(begin)
                .append(keyIndex)
                .append(hash.length)
                .append(hash)
                .append(signature.length)
                .append(signature)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALVERIFY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SM2内部密钥验证签名失败，错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            return false;
        }
        return true;
    }

    /**
     * SM2验证签名 外部密钥
     *
     * @param data         待验证签名的原始数据
     * @param signature    待验证签名的签名数据
     * @param sm2PublicKey 外部公钥
     * @return true ：验证签名成功，false ：验证签名失败
     * @throws AFCryptoException AFCryptoException
     */
    public boolean SM2VerifyByCertPubKey(byte[] data, byte[] signature, SM2PublicKey sm2PublicKey) throws AFCryptoException {  //success
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.sm3HashWithPubKey(data, sm2PublicKey, ConstantNumber.DEFAULT_USER_ID.getBytes(StandardCharsets.UTF_8));
        int zero = 0;
        byte[] param = new BytesBuffer()
                .append(zero)
                .append(ConstantNumber.SGD_SM2_1)
                .append(zero)
                .append(sm2PublicKey.size())
                .append(sm2PublicKey.encode())
                .append(hash.length)
                .append(hash)
                .append(signature.length)
                .append(signature)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALVERIFY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SM2外部公钥验证签名失败，错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            return false;
        }
        return true;

    }

    /**
     * <p>基于证书的SM2文件签名</p>
     *
     * @param data         待签名的文件
     * @param privateKey   签名的私钥
     * @param sm2PublicKey 签名的公钥
     * @return 签名数据
     */
    public byte[] sm2SignFileByCertificate(byte[] data, byte[] privateKey, byte[] sm2PublicKey) throws AFCryptoException {
        logger.info("SV-CMD 基于证书的SM2文件签名, data: {}, privateKey: {}, sm2PublicKey: {}", data, privateKey, sm2PublicKey);
        int zero = 0;
        //hash
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.sm3HashWithPubKey(data, new SM2PublicKey(sm2PublicKey), ConstantNumber.DEFAULT_USER_ID.getBytes(StandardCharsets.UTF_8));

        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALSIGN_ECC, new BytesBuffer()
                .append(zero)
                .append(ConstantNumber.SGD_SM2_1)
                .append(zero)
                .append(privateKey.length)
                .append(privateKey)
                .append(hash.length)
                .append(hash)
                .toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("基于证书的SM2文件签名失败, 错误码: {}, 错误信息: {}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("基于证书的SM2文件签名失败");
        }
        return res.getDataBuffer().readOneData();
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
        logger.info("基于证书的SM2验证签名");
        //读取证书数据
        byte[] derCert = BytesOperate.base64DecodeCert(new String(base64Certificate));
        InputStream input = new ByteArrayInputStream(derCert);
        ASN1Sequence seq = null;
        try (ASN1InputStream aln = new ASN1InputStream(input)) {
            seq = (ASN1Sequence) aln.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            byte[] encodePubKey = cert.getSubjectPublicKeyInfo().getPublicKeyData().getEncoded();

            SM2PublicKey sm2PublicKey = new SM2PublicKey();
            byte[] sm2PubKey = new byte[4 + 32 + 32];
            System.arraycopy(BytesOperate.int2bytes(256), 0, sm2PubKey, 0, 4);
            System.arraycopy(encodePubKey, 4, sm2PubKey, 4, 64);
            sm2PublicKey.decode(sm2PubKey);
            return this.SM2VerifyByCertPubKey(data, signature, sm2PublicKey);
        } catch (Exception e) {
            logger.error("基于证书的SM2验证签名失败，错误信息:{}", e.getMessage());
            throw new AFCryptoException("基于证书的SM2验证签名失败");
        }
    }

    /**
     * SM2文件签名 内部密钥
     * <p>SM2文件签名</p>
     * <p>使用签名服务器内部密钥对文件进行 SM2签名运算</p>
     *
     * @param index ：待签名的签名服务器内部密钥索引
     * @param data  ：待签名的文件
     * @return ： base64编码的签名数据
     */
    public byte[] sm2SignFile(int index, byte[] data) throws AFCryptoException {  //success
        return sm2Signature(index, data);
    }

    /**
     * SM2文件签名 外部密钥
     * <p>SM2文件签名</p>
     * <p>使用外部密钥对文件进行 SM2签名运算</p>
     *
     * @param data       ：待签名的文件
     * @param privateKey ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                   <p>SM2PrivateKey ::= INTEGER</p>
     * @return ： base64编码的签名数据
     */
    public byte[] sm2SignFile(byte[] data, byte[] privateKey) throws AFCryptoException { //success
        return sm2Signature(data, privateKey);
    }


    /**
     * SM2内部密钥加密
     *
     * @param keyIndex ：密码设备内部密钥索引
     * @param inData   ：待加密的数据原文
     * @return ：Base64编码的密文数据
     */
    public byte[] sm2Encrypt(int keyIndex, byte[] inData) throws AFCryptoException {  //success
        logger.info("sm2Encrypt,keyIndex:{},inDataLen:{}", keyIndex, inData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_3)
                .append(0)
                .append(0)
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALENCRYPT_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-sm2内部加密错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-sm2内部加密错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * SM2 外部密钥加密
     *
     * @param publicKey ：base64编码的SM2公钥数据, 其结构应满足 GM/T 0009-2012中关于SM2公钥结构的数据定义
     *                  <p>SM2PublicKey ::= BIT STRING</p> 其结构为 04||X||Y
     * @param inData    ：待加密的数据原文
     * @return ：Base64编码的密文数据
     */
    public byte[] sm2Encrypt(SM2PublicKey publicKey, byte[] inData) throws AFCryptoException {  //success
        logger.info("SV-sm2外部加密,publicKey:{},inDataLen:{}", publicKey, inData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(ConstantNumber.SGD_SM2_3)
                .append(0)
                .append(publicKey.size())
                .append(publicKey.encode())
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALENCRYPT_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-sm2外部加密错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-sm2外部加密错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * SM2 内部密钥解密
     *
     * @param keyIndex  密钥索引
     * @param SM2Cipher 密文
     */
    public byte[] sm2Decrypt(int keyIndex, SM2Cipher SM2Cipher) throws AFCryptoException {  //success
        logger.info("SV-sm2内部解密,keyIndex:{},SM2CipherLen:{}", keyIndex, SM2Cipher.size());
        getPrivateAccess(keyIndex, 3);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_3)
                .append(0)
                .append(0)
                .append(SM2Cipher.size())
                .append(SM2Cipher.encode())
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALDECRYPT_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-sm2内部解密错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-sm2内部解密错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * SM2 外部密钥解密
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
    public byte[] sm2Decrypt(SM2PrivateKey privateKey, SM2Cipher encData) throws AFCryptoException { //success
        logger.info("SV-sm2外部解密,privateKey:{},encDataLen:{}", privateKey, encData.size());
        byte[] param = new BytesBuffer()
                .append(0)
                .append(ConstantNumber.SGD_SM2_3)
                .append(0)
                .append(privateKey.size())
                .append(privateKey.encode())
                .append(encData.size())
                .append(encData.encode())
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALDECRYPT_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-sm2外部解密错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-sm2外部解密错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 导出SM2加密公钥
     *
     * @param keyIndex 密钥索引
     */
    public byte[] getSM2EncPublicKey(int keyIndex) throws AFCryptoException {  //success
        logger.info("SV-导出SM2加密公钥,keyIndex:{}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_2)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTENCPUBLICKEY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出SM2加密公钥错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出SM2加密公钥错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 导出SM2签名公钥
     *
     * @param keyIndex 密钥索引
     */
    public byte[] getSM2SignPublicKey(int keyIndex) throws AFCryptoException {  //success
        logger.info("SV-导出SM2签名公钥,keyIndex:{}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_1)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTSIGNPUBLICKEY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出SM2签名公钥错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出SM2签名公钥错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 获取所有 CA 证书的别名
     */
    public CertAltNameTrustList getCertTrustListAltName() throws AFCryptoException {  //success
        logger.info("SV-查询证书信任列表别名");
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_ALL_ALT_NAME, null, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-查询证书信任列表别名错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-查询证书信任列表别名错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();
        int nameNumber = BytesOperate.bytes2int(getBytes(responseData, 0, 4));
        int certListLen = BytesOperate.bytes2int(getBytes(responseData, 4, 4));
        byte[] certList = getBytes(responseData, 4 + 4, certListLen);
        return new CertAltNameTrustList(certList, nameNumber);
    }


    /**
     * 根据证书别名获取证书
     * 根据证书别名获取证书个数
     *
     * @param subCmd  0x01：获取证书个数；0x02：获取证书
     * @param index   证书索引
     * @param altName 证书别名
     * @return 证书列表
     */
    public CertList getCertListByAltName(int subCmd, int index, byte[] altName) throws AFCryptoException { //
        logger.info("SV-根据证书别名获取信任证书的个数,altName:{}", altName);
        BytesBuffer buffer = new BytesBuffer()
                .append(subCmd);
        if (subCmd == 0x02) {
            buffer.append(index);
        }
        byte[] param = buffer
                .append(altName.length)
                .append(altName)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-根据证书别名获取信任证书的个数错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-根据证书别名获取信任证书的个数错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();
        CertList list = new CertList();
        if (subCmd == 0x01) {
            list.setCertCount(BytesOperate.bytes2int(getBytes(responseData, 0, 4)));
        } else {
            list.setCertData(res.getDataBuffer().readOneData());
        }
        return list;
    }

    /**
     * 获取应用实体信息
     * <p>获取应用策略</p>
     * <p>根据策略名称获取应用策略，此应用策略为用户在管理程序中创建。用户获取应用策略后，签名服务器会根据用户设定的策略内容进行相关的服务操作</p>
     *
     * @param policyName ：策略名称
     */

    public AFSvCryptoInstance getInstance(byte[] policyName) throws AFCryptoException {
        logger.info("SV-获取应用策略,policyName:{}", policyName);
        byte[] param = new BytesBuffer()
                .append(policyName.length)
                .append(policyName)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_INSTANCE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取应用策略错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取应用策略错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();
        AFSvCryptoInstance instance = new AFSvCryptoInstance();

        //todo  在实体里面decode
        instance.setPolicyName(policyName);
        instance.setKeyIndex(BytesOperate.bytes2int(getBytes(responseData, 0, 4)));
        instance.setKeyType(BytesOperate.bytes2int(getBytes(responseData, 4, 4)));
        instance.setPolicy(BytesOperate.bytes2int(getBytes(responseData, 4 + 4, 4)));

        return instance;

    }

//    /**
//     * <p>删除用户证书列表</p>
//     * <p>根据证书别名删除证书列表</p>
//     *
//     * @param altName ：证书列表别名
//     */
//
//    public void deleteCertList(byte[] altName) throws AFCryptoException {
//        logger.info("SV-删除用户证书列表,altName:{}", altName);
//        byte[] param = new BytesBuffer()
//                .append(altName.length)
//                .append(altName)
//                .toBytes();
//        RequestMessage req = new RequestMessage(CMDCode.CMD_DELETE_CERT, param, agKey);
//        ResponseMessage res = client.send(req);
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("SV-删除用户证书列表错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("SV-删除用户证书列表错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//    }


    /**
     * 获取应用实体证书数据
     * <p>根据策略名称，获取相应的证书</p>
     *
     * @param policyName : 策略名称
     * @param certType   : 证书类型 1|加密证书; 2|签名证书
     * @return : Base64编码的证书
     */
    public byte[] getCertByPolicyName(byte[] policyName, int certType) throws AFCryptoException { //success
        logger.info("SV-根据策略名称(应用实体)，获取相应的证书,policyName:{},certType(1|加密证书; 2|签名证书):{}", policyName, certType);
        byte[] param = new BytesBuffer()
                .append(policyName.length)
                .append(policyName)
                .append(certType)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_BY_POLICY_NAME, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-根据策略名称，获取相应的证书错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-根据策略名称，获取相应的证书错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 获取证书信息
     *
     * @param base64Certificate ：Base64编码的证书文件
     * @param certInfoType      : 用户待获取的证书内容类型 : 类型定义在类{@link com.af.constant.CertParseInfoType}
     * @return ：用户获取到的证书信息内容
     */
    public byte[] getCertInfo(byte[] base64Certificate, int certInfoType) throws AFCryptoException { //success
        logger.info("SV-获取证书信息,base64Certificate:{},certInfoType:{}", base64Certificate, certInfoType);
        byte[] param = new BytesBuffer()
                .append(certInfoType)
                .append(base64Certificate.length)
                .append(base64Certificate)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_INFO, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取证书信息错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取证书信息错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] bytes = res.getDataBuffer().readOneData();
        return new String(bytes).toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);

    }

    /**
     * 根据 OID 获取证书信息
     *
     * @param certData ：Base64编码的证书文件
     * @param oid      : 用户待获取的证书内容类型OID值 : OID值定义在类 certParseInfoType 中
     * @return ：用户获取到的证书信息内容
     */
    public byte[] getCertInfoByOid(byte[] certData, byte[] oid) throws AFCryptoException { //success
        logger.info("SV-获取证书扩展信息,certData:{},oid:{}", certData, oid);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(oid.length)
                .append(oid)
                .append(certData.length)
                .append(certData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_EXT_TYPE_INFO, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取证书扩展信息错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取证书扩展信息错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();

    }

    /**
     * 获取设备证书
     *
     * @param usage ：证书用途 2|签名证书 ; 3|加密证书
     * @return ：Base64编码的证书
     */
    public byte[] getServerCertByUsage(int usage) throws AFCryptoException { //success
        logger.info("SV-获取设备证书,usage(2|签名证书 ; 3|加密证书):{}", usage);
        byte[] param = new BytesBuffer()
                .append(usage)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_SERVER_CERT_INFO, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取服务器证书错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取服务器证书错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * PKCS7 签名信息编码
     * <p>编码签名数据</p>
     * <p>编码基于SM2算法的签名数据</p>
     *
     * @param keyType    ：消息签名格式，1|带原文，0|不带原文
     * @param privateKey ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                   <p>SM2PrivateKey ::= INTEGER</p>
     * @param certData   ：Base64编码的签名者证书
     * @param data       ：需要签名的数据
     * @return ：Base64编码的签名数据
     */
    public byte[] encodeSignedDataForSM2(int keyType, SM2PrivateKey privateKey, byte[] certData, byte[] data) throws AFCryptoException { //success
        logger.info("SV-编码签名数据, keyType(1|带原文，0|不带原文): {}, signerCertificate: {}, data: {}", keyType, certData, data);
        byte[] param = new BytesBuffer()
                .append(keyType)
                .append(privateKey.encode())
                .append(0)
                .append(certData.length)
                .append(certData)
                .append(ConstantNumber.SGD_SM3)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_SM2_SIGNDATA_ENCODE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-编码签名数据,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-编码签名数据,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * PKCS7 签名信息解码
     * <p>解码签名数据</p>
     * <p>解码基于SM2算法的签名数据</p>
     *
     * @param signedData ：Base64编码的签名数据，其格式应符合GM/T 0010《SM2密码算法加密签名消息语法规范》中SignedData的数据类型定义
     * @return ：解码后的数据，包括签名者证书，HASH算法标识，被签名的数据以及签名值
     */
    public AFSM2DecodeSignedData decodeSignedDataForSM2(byte[] signedData) throws AFCryptoException { //success
        logger.info("SV-解码签名数据, signedData: {}", signedData);
        byte[] param = new BytesBuffer()
                .append(signedData.length)
                .append(signedData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_SM2_SIGNDATA_DECODE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-解码签名数据,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-解码签名数据,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();

        //签名证书长度
        int certLen = BytesOperate.bytes2int(responseData);
        //签名证书
        byte[] certData = getBytes(responseData, 4, certLen);
        //HASH算法标识
        int hashAlgID = BytesOperate.bytes2int(responseData, 4 + certLen);
        //原文数据长度
        int rawDataLen = BytesOperate.bytes2int(responseData, 4 + certLen + 4);
        //原文数据
        byte[] rawData = getBytes(responseData, 4 + certLen + 4 + 4, rawDataLen);
        //签名数据长度
        int signDataLen = BytesOperate.bytes2int(responseData, 4 + certLen + 4 + 4 + rawDataLen);
        //签名数据
        byte[] result = getBytes(responseData, 4 + certLen + 4 + 4 + rawDataLen + 4, signDataLen);

        return new AFSM2DecodeSignedData(rawData, BytesOperate.base64EncodeCert(certData), hashAlgID, BytesOperate.base64EncodeData(result));
    }

    /**
     * PKCS7 签名信息验证
     * <p>验证签名数据</p>
     *
     * @param rawData  原文数据
     * @param signData 签名数据
     */
    public boolean verifySignedDataForSM2(byte[] rawData, byte[] signData) throws AFCryptoException { //success
        logger.info("SV-验证签名数据, rawData: {}, signData: {}", rawData, signData);

        int rawDataLen = null == rawData ? 0 : rawData.length;

        BytesBuffer buffer = new BytesBuffer()
                .append(signData.length)
                .append(signData)
                .append(rawDataLen);
        if (rawDataLen > 0) {
            buffer.append(rawData);
        }
        byte[] param = buffer.toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_SM2_SIGNDATA_VERIFY, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-验证签名数据,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-验证签名数据,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return true;


    }

    /**
     * PKCS7 带签名信息的数字信封编码
     * <p>编码数字信封</p>
     * <p>编码基于SM2算法的数字信封</p>
     *
     * @param privateKey:私钥数据
     * @param symmetricKey:对称密钥数据
     * @param signCert            :签名证书
     * @param encryptCert         :加密证书
     * @param data                :原文数据
     * @return :编码后的数字信封数据
     */
    public byte[] encodeEnvelopedDataForSM2(byte[] privateKey, byte[] symmetricKey, byte[] signCert, byte[] encryptCert, byte[] data) throws AFCryptoException { //success
        logger.info("SV-编码数字信封, privateKey: {}, symmetricKey: {}, signCert: {}, encryptCert: {}, dataLen: {}", privateKey, symmetricKey, signCert, encryptCert, data.length);
        byte[] param = new BytesBuffer()
                .append(privateKey.length)
                .append(privateKey)
                .append(symmetricKey.length)
                .append(symmetricKey)
                .append(0)
                .append(signCert.length)
                .append(signCert)
                .append(ConstantNumber.SGD_SM3)
                .append(encryptCert.length)
                .append(encryptCert)
                .append(0)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.PKCS7_ENCODE_WITH_SIGN, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-编码数字信封,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-编码数字信封,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * PKCS7 带签名信息的数字信封解码
     *
     * @param privateKey:私钥数据
     * @param encodeData      :编码后的数字信封数据
     */
    public byte[] decodeEnvelopedDataForSM2(byte[] privateKey, byte[] encodeData) throws AFCryptoException { //success
        logger.info("SV-解码数字信封, privateKey: {}, encodeData: {}", privateKey, encodeData);
        byte[] param = new BytesBuffer()
                .append(privateKey.length)
                .append(privateKey)
                .append(encodeData.length)
                .append(encodeData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.PKCS7_DECODE_WITH_SIGN, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-解码数字信封,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-解码数字信封,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    //=============================2023 05 31 根据协议新增  todo 后续可精简为cmd层和协议文档 一一对应,从Device层做业务区分================================


    /**
     * 导出公钥信息
     *
     * @param index     密钥索引
     * @param algorithm 算法标识
     */
    public byte[] exportPublicKey(int index, Algorithm algorithm) throws AFCryptoException {
        logger.info("SV-导出公钥信息, index: {}, keyType: {}", index, algorithm);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(algorithm.getValue())
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.EXPORT_PUBLIC_KEY, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出公钥信息,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出公钥信息,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 生成密钥对
     *
     * @param algorithm     算法标识SGD_RSA|SGD_SM2|SGD_SM2_1|SGD_SM2_2|SGD_SM2_3
     * @param modulusLength 模量长度 RSA 1024|2048|   SM2 256
     * @return 1、4 字节公钥信息长度
     * 2、公钥信息
     * 3、4 字节私钥信息长度
     * 4、私钥信息
     */
    public byte[] generateKeyPair(Algorithm algorithm, ModulusLength modulusLength) throws AFCryptoException {
        logger.info("SV-生成密钥对, keyType: {}, modulusLength: {}", algorithm, modulusLength.getLength());
        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(modulusLength.getLength())
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATEKEYPAIR_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-生成密钥对,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-生成密钥对,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }


    /**
     * 释放密钥信息
     *
     * @param keyIndex 密钥索引
     */
    public void freeKey(int keyIndex) throws AFCryptoException {
        logger.info("SV-释放密钥信息, keyIndex: {}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_DESTROYKEY, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-释放密钥信息,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-释放密钥信息,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
    }


    /**
     * RSA 公钥操作
     *
     * @param keyIndex  密钥索引 外部密钥传0
     * @param pubKey    公钥    内部密钥传null
     * @param algorithm 算法标识  SGD_RSA_ENC|SGD_RSA_SIGN
     * @param data      数据
     */
    public byte[] rsaPublicKeyOperation(int keyIndex, RSAPubKey pubKey, Algorithm algorithm, byte[] data) throws AFCryptoException {
        logger.info("SV-RSA 公钥操作, keyIndex: {}, pubKey: {}, keyType: {}, data: {}", keyIndex, pubKey, algorithm, data);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(algorithm.getValue())
                .append(0)
                .append(null == pubKey ? 0 : pubKey.size())
                .append(null == pubKey ? null : pubKey.encode())
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.RSA_PUBLIC_KEY_OPERATE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA 公钥操作,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA 公钥操作,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * RSA 私钥操作 签名|解密
     *
     * @param keyIndex  密钥索引 外部密钥传0
     * @param priKey    私钥    内部密钥传null
     * @param algorithm 算法标识 SGD_RSA_ENC|SGD_RSA_SIGN
     * @param data      数据
     */
    public byte[] rsaPrivateKeyOperation(int keyIndex, RSAPriKey priKey, Algorithm algorithm, byte[] data) throws AFCryptoException {
        logger.info("SV-RSA 私钥操作, keyIndex: {}, priKey: {}, keyType: {}, data: {}", keyIndex, priKey, algorithm, data);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(algorithm.getValue())
                .append(0)
                .append(null == priKey ? 0 : priKey.size())
                .append(null == priKey ? null : priKey.encode())
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.RSA_PRIVATE_KEY_OPERATE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA 私钥操作,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA 私钥操作,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * 验证证书二
     */
    public void verifyCertificate2() throws AFCryptoException {
        logger.info("SV-验证证书二");

    }


    //================================================工具======================================
    private static byte[] getBytes(byte[] bytesResponse, int offset, int length) {
        return BytesOperate.subBytes(bytesResponse, offset, length);
    }

}
