package com.af.device.cmd;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.constant.ConstantNumber;
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
public class AFSVCmd {

    private static final Logger logger = LoggerFactory.getLogger(AFSVCmd.class);
    private final AFNettyClient client;
    private byte[] agkey;

    public AFSVCmd(AFNettyClient client, byte[] agkey) {
        this.client = client;
        this.agkey = agkey;
    }

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * 获取设备信息异常
     */
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        return null;
    }

    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * 获取随机数异常
     */
    public byte[] getRandom(int length) throws AFCryptoException {
        logger.info("SV-获取随机数, length:{}", length);
        byte[] param = new BytesBuffer().append(length).toBytes();

        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATERANDOM, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取随机数失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取随机数失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p>验证证书有效性</p>
     *
     * <p>验证证书有效性，通过OCSP模式获取当前证书的有效性。 注：选择此方式验证证书有效性，需连接互联网，或者可以访问到待测证书的OCSP服务器</p>
     *
     * @param base64Certificate : 待验证的证书--BASE64编码格式
     * @return ：返回证书验证结果，0为验证通过
     */

    public int validateCertificate(byte[] base64Certificate) throws AFCryptoException {
        logger.info("SV-验证证书有效性, base64Certificate:{}", base64Certificate);
        byte[] param = new BytesBuffer().append(base64Certificate.length)
                .append(base64Certificate)
                .toBytes();

        param = SM4Utils.encrypt(param, agkey);
        RequestMessage req = new RequestMessage(CMDCode.CMD_VERIFY_CERT, param);
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

    public boolean isCertificateRevoked(byte[] base64Certificate, byte[] crlData) throws CertificateException, AFCryptoException {
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
     * <p>导入CA证书</p>
     * <p>导入CA证书</p>
     *
     * @param caAltName           :           ca证书别名
     * @param base64CaCertificate ： 待导入的CA证书--BASE64编码格式
     * @return ：返回CA证书导入结果，0为导入成功
     */

    public int addCaCertificate(byte[] caAltName, byte[] base64CaCertificate) throws AFCryptoException {
        logger.info("SV-导入CA证书, caAltName:{}, base64CaCertificate:{}", caAltName, base64CaCertificate);
        byte[] param = new BytesBuffer().append(caAltName.length)
                .append(caAltName)
                .append(base64CaCertificate.length)
                .append(base64CaCertificate)
                .toBytes();

        RequestMessage req = new RequestMessage(CMDCode.CMD_ADD_CA_CERT, SM4Utils.encrypt(agkey, param));
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-导入CA证书失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导入CA证书失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        } else {
            return 0;
        }
    }

    /**
     * <p>导出RSA公钥</p>
     * <p>导出密码机内部对应索引和用途的RSA公钥信息</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param keyUsage ：密钥用途，0：签名公钥；1：加密公钥
     * @return : 返回Base64编码的公钥数据
     */

    public byte[] getRSAPublicKey(int keyIndex, int keyUsage) throws AFCryptoException {
        logger.info("SV-导出RSA公钥, keyIndex:{}, keyUsage:{}", keyIndex, keyUsage);
        int type = ConstantNumber.SGD_RSA_SIGN;
        int cmdID = CMDCode.CMD_EXPORTSIGNPUBLICKEY_RSA;
        if (keyUsage == ConstantNumber.ENC_PUBLIC_KEY) {
            type = ConstantNumber.SGD_RSA_ENC;
        }
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(type)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(cmdID, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出RSA公钥失败, 错误码:{}, 错误信息:{}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出RSA公钥失败, 错误码:" + responseMessage.getHeader().getErrorCode() + ", 错误信息:" + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
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
                .append(0)
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALPRIVATEKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA签名失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA签名失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();

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

    public byte[] rsaSignature(RSAPriKey privateKey, byte[] inData) throws AFCryptoException {
        logger.info("SV-RSA签名, privateKeyLen:{}, inDataLen:{}", privateKey, inData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(0)
                .append(0)
                .append(privateKey.size())
                .append(privateKey.encode())
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPRIVATEKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA签名失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA签名失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
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

    public boolean rsaVerify(int keyIndex, byte[] inData, byte[] signatureData) throws AFCryptoException {
        logger.info("SV-RSA验签, keyIndex:{}, inDataLen:{}, signatureDataLen:{}", keyIndex, inData.length, signatureData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_RSA_SIGN)
                .append(0)
                .append(0)
                .append(signatureData.length)
                .append(signatureData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALPUBLICKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA验签失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA验签失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return Arrays.equals(res.getDataBuffer().readOneData(), inData);
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

    public boolean rsaVerify(RSAPubKey publicKey, byte[] inData, byte[] signatureData) throws AFCryptoException {
        logger.info("SV-RSA验签, publicKey:{}, inDataLen:{}, signatureDataLen:{}", publicKey, inData.length, signatureData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(0)
                .append(0)
                .append(publicKey.size())
                .append(publicKey.encode())
                .append(signatureData.length)
                .append(signatureData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPUBLICKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA验签失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA验签失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return Arrays.equals(res.getDataBuffer().readOneData(), inData);
    }


    /**
     * <p>RSA加密</p>
     * <p>使用内部密钥进行RSA加密</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param inData   ：待加密的原始数据
     * @return ：Base64编码的加密数据
     */

    public byte[] rsaEncrypt(int keyIndex, byte[] inData) throws AFCryptoException {
        logger.info("SV-RSA加密, keyIndex:{}, inDataLen:{}", keyIndex, inData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_RSA_ENC)
                .append(0)
                .append(0)
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALPUBLICKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA加密失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA加密失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
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

    public byte[] rsaEncrypt(RSAPubKey publicKey, byte[] inData) throws AFCryptoException {
        logger.info("SV-RSA加密, publicKey:{}, inDataLen:{}", publicKey, inData.length);

        byte[] param = new BytesBuffer()
                .append(0)
                .append(0)
                .append(0)
                .append(publicKey.size())
                .append(publicKey.encode())
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPUBLICKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA加密失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA加密失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * <p>RSA解密</p>
     * <p>使用内部密钥进行RSA解密</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param encData  ：Base64编码的加密数据
     * @return ：原始数据
     */

    public byte[] rsaDecrypt(int keyIndex, byte[] encData) throws AFCryptoException {
        logger.info("SV-RSA解密, keyIndex:{}, encDataLen:{}", keyIndex, encData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_RSA_ENC)
                .append(0)
                .append(0)
                .append(encData.length)
                .append(encData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALPRIVATEKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA解密失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA解密失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
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

    public byte[] rsaDecrypt(RSAPriKey privateKey, byte[] encData) throws AFCryptoException {
        logger.info("SV-RSA解密, privateKey:{}, encDataLen:{}", privateKey, encData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(0)
                .append(0)
                .append(privateKey.size())
                .append(privateKey.encode())
                .append(encData.length)
                .append(encData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPRIVATEKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-RSA解密失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA解密失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();


    }

    /**
     * <p>SM2内部密钥签名</p>
     * <p>使用签名服务器内部密钥进行 SM2签名运算</p>
     *
     * @param index ：待签名的签名服务器内部密钥索引
     * @param data  ：待签名的数据
     * @return ： base64编码的签名数据
     */

    public byte[] sm2Signature(int index, byte[] data) throws AFCryptoException {
        logger.info("SM2内部密钥签名, index: {}, data: {}", index, data);
        getPrivateAccess(index);
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.SM3Hash(data);
        int begin = 1;
        byte[] param = new BytesBuffer()
                .append(begin)
                .append(index)
                .append(hash.length)
                .append(hash)
                .toBytes();

        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_INTERNALSIGN_ECC, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM2内部密钥签名失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2内部密钥签名失败");
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * 获取私钥访问权限
     *
     * @param index 索引
     */
    private void getPrivateAccess(int index) throws AFCryptoException {
        String pwd = "12345678";
        byte[] param = new BytesBuffer()
                .append(index)
                .append(pwd.length())
                .append(pwd.getBytes(StandardCharsets.UTF_8))
                .toBytes();

        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GETPRIVATEKEYACCESSRIGHT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取私钥访问权限失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取私钥访问权限失败");
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

    public byte[] sm2Signature(byte[] data, byte[] privateKey) throws AFCryptoException {
        logger.info("SM2外部密钥签名, data: {}, privateKey: {}", data, privateKey);
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.SM3Hash(data);
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
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALSIGN_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SM2外部密钥签名失败, 错误码: {}, 错误信息: {}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2外部密钥签名失败");
        }
        return res.getDataBuffer().readOneData();
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

    public byte[] sm2SignatureByCertificate(byte[] data, byte[] privateKey, byte[] base64Certificate) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>SM2文件签名</p>
     * <p>使用签名服务器内部密钥对文件进行 SM2签名运算</p>
     *
     * @param index ：待签名的签名服务器内部密钥索引
     * @param data  ：待签名的文件
     * @return ： base64编码的签名数据
     */

    public byte[] sm2SignFile(int index, byte[] data) throws AFCryptoException {
        logger.info("SM2文件签名, index: {}, data: {}", index, data);
        getPrivateAccess(index);
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.SM3Hash(data);
        int begin = 1;
        byte[] param = new BytesBuffer()
                .append(begin)
                .append(index)
                .append(hash.length)
                .append(hash)
                .toBytes();

        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALSIGN_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SM2内部密钥文件签名失败, 错误码: {}, 错误信息: {}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2文件签名失败");
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p>SM2文件签名</p>
     * <p>使用外部密钥对文件进行 SM2签名运算</p>
     *
     * @param data       ：待签名的文件
     * @param privateKey ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                   <p>SM2PrivateKey ::= INTEGER</p>
     * @return ： base64编码的签名数据
     */

    public byte[] sm2SignFile(byte[] data, byte[] privateKey) throws AFCryptoException {
        logger.info("SM2文件签名, data: {}, privateKey: {}", data, privateKey);
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.SM3Hash(data);
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

        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALSIGN_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SM2外部密钥文件签名失败, 错误码: {}, 错误信息: {}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2文件签名失败");
        }
        return res.getDataBuffer().readOneData();

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
        logger.info("基于证书的SM2文件签名, data: {}, privateKey: {}, sm2PublicKey: {}", data, privateKey, sm2PublicKey);
        int zero = 0;
        //hash
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.SM3HashWithPubKey(data, new SM2PublicKey(sm2PublicKey), ConstantNumber.DEFAULT_USER_ID.getBytes(StandardCharsets.UTF_8));

        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALSIGN_ECC, new BytesBuffer()
                .append(zero)
                .append(ConstantNumber.SGD_SM2_1)
                .append(zero)
                .append(privateKey.length)
                .append(privateKey)
                .append(hash.length)
                .append(hash)
                .toBytes());
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("基于证书的SM2文件签名失败, 错误码: {}, 错误信息: {}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("基于证书的SM2文件签名失败");
        }
        return res.getDataBuffer().readOneData();
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
        logger.info("SV-SM2内部密钥验证签名");
        getPrivateAccess(keyIndex);
        int begin = 1;
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.SM3Hash(data);
        byte[] param = new BytesBuffer()
                .append(begin)
                .append(keyIndex)
                .append(hash.length)
                .append(hash)
                .append(signature.length)
                .append(signature)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_INTERNALVERIFY_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SM2内部密钥验证签名失败，错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            return false;
        }
        return true;
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
     * SM2验证签名 外部公钥
     *
     * @param data         待验证签名的原始数据
     * @param signature    待验证签名的签名数据
     * @param sm2PublicKey 外部公钥
     * @return true ：验证签名成功，false ：验证签名失败
     * @throws AFCryptoException AFCryptoException
     */
    public boolean SM2VerifyByCertPubKey(byte[] data, byte[] signature, SM2PublicKey sm2PublicKey) throws AFCryptoException {
        AFHsmDevice afHsmDevice = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        byte[] hash = afHsmDevice.SM3HashWithPubKey(data, sm2PublicKey, ConstantNumber.DEFAULT_USER_ID.getBytes(StandardCharsets.UTF_8));
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
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALVERIFY_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SM2外部公钥验证签名失败，错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            return false;
        }
        return true;

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

    public byte[] sm2Encrypt(int keyIndex, byte[] inData) throws AFCryptoException {
        logger.info("sm2Encrypt,keyIndex:{},inDataLen:{}", keyIndex, inData.length);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_3)
                .append(0)
                .append(0)
                .append(inData.length)
                .append(inData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALENCRYPT_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-sm2内部加密错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-sm2内部加密错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
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

    public byte[] sm2Encrypt(SM2PublicKey publicKey, byte[] inData) throws AFCryptoException {
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
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALENCRYPT_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-sm2外部加密错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-sm2外部加密错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
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
        return new byte[0];
    }


    /**
     * sm2 内部解密
     *
     * @param keyIndex  密钥索引
     * @param SM2Cipher 密文
     */
    public byte[] sm2Decrypt(int keyIndex, SM2Cipher SM2Cipher) throws AFCryptoException {
        logger.info("SV-sm2内部解密,keyIndex:{},SM2CipherLen:{}", keyIndex, SM2Cipher.size());
        getPrivateAccess(keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_3)
                .append(0)
                .append(0)
                .append(SM2Cipher.size())
                .append(SM2Cipher.encode())
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALDECRYPT_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-sm2内部解密错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-sm2内部解密错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
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

    public byte[] sm2Decrypt(SM2PrivateKey privateKey, SM2Cipher encData) throws AFCryptoException {
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
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALDECRYPT_ECC, param);
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
    public byte[] getSM2EncPublicKey(int keyIndex) throws AFCryptoException {
        logger.info("SV-导出SM2加密公钥,keyIndex:{}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_2)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTENCPUBLICKEY_ECC, param);
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
    public byte[] getSM2SignPublicKey(int keyIndex) throws AFCryptoException {
        logger.info("SV-导出SM2签名公钥,keyIndex:{}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_1)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTSIGNPUBLICKEY_ECC, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出SM2签名公钥错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出SM2签名公钥错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p>查询证书信任列表别名</p>
     * <p>查询证书信任列表别名</p>
     *
     * @return 信任列表别名组合，如： CA001|CA002|CA003
     */

    public certAltNameTrustList getCertTrustListAltName() throws AFCryptoException {
        logger.info("SV-查询证书信任列表别名");
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_ALL_ALT_NAME, null);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-查询证书信任列表别名错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-查询证书信任列表别名错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();
        int nameNumber = BytesOperate.bytes2int(getBytes(responseData, 0, 4));
        int certListLen = BytesOperate.bytes2int(getBytes(responseData, 4, 4));
        byte[] certList = getBytes(responseData, 4 + 4, certListLen);

        return new certAltNameTrustList(certList, nameNumber);
    }

    private static byte[] getBytes(byte[] bytesResponse, int offset, int length) {
        return BytesOperate.subBytes(bytesResponse, offset, length);
    }


    /**
     * 根据证书别名获取证书列表
     * @param subCmd 0x01：获取证书个数；0x02：获取证书列表
     * @param index 证书索引
     * @param altName 证书别名
     * @return 证书列表
     */
    public CertList getCertListByAltName(int subCmd, int index, byte[] altName) throws AFCryptoException {
        logger.info("SV-根据证书别名获取信任证书的个数,altName:{}", altName);
        BytesBuffer buffer = new BytesBuffer().append(subCmd);
        if (subCmd != 0x01) {
            buffer.append(index);
        }
        byte[] param = buffer.append(altName.length).append(altName).toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT, param);
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
            int certLen = BytesOperate.bytes2int(getBytes(responseData, 0, 4));
            list.setCertData(getBytes(responseData, 4, certLen));
        }
        return list;
    }




    /**
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
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_INSTANCE, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取应用策略错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取应用策略错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();
        AFSvCryptoInstance instance = new AFSvCryptoInstance();
        instance.setPolicyName(policyName);
        instance.setKeyIndex(BytesOperate.bytes2int(getBytes(responseData, 0, 4)));
        instance.setKeyType(BytesOperate.bytes2int(getBytes(responseData, 4, 4)));
        instance.setPolicy(BytesOperate.bytes2int(getBytes(responseData, 4 + 4, 4)));

        return instance;

    }

    /**
     * <p>删除用户证书列表</p>
     * <p>根据证书别名删除证书列表</p>
     *
     * @param altName ：证书列表别名
     */

    public void deleteCertList(byte[] altName) throws AFCryptoException {
        logger.info("SV-删除用户证书列表,altName:{}", altName);
        byte[] param = new BytesBuffer()
                .append(altName.length)
                .append(altName)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_DELETE_CERT, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-删除用户证书列表错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-删除用户证书列表错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
    }

    /**
     * <p>获取服务器证书</p>
     * <p>读取当前应用的服务器的签名证书，如果有签名证书则得到签名证书，否则得到加密证书</p>
     *
     * @return ：Base64编码的服务器证书
     */

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

    public byte[] getServerCertByUsage(int usage) throws AFCryptoException {
        logger.info("SV-获取服务器证书,usage:{}", usage);
        byte[] param = new BytesBuffer()
                .append(usage)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_SERVER_CERT_INFO, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取服务器证书错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取服务器证书错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p>根据策略名称，获取相应的证书</p>
     * <p>根据策略名称，获取相应的证书</p>
     *
     * @param policyName : 策略名称
     * @param certType   : 证书类型 1：加密证书，2：签名证书
     * @return : Base64编码的证书
     */

    public byte[] getCertByPolicyName(byte[] policyName, int certType) throws AFCryptoException {
        logger.info("SV-根据策略名称，获取相应的证书,policyName:{},certType:{}", policyName, certType);
        byte[] param = new BytesBuffer()
                .append(policyName.length)
                .append(policyName)
                .append(certType)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_BY_POLICY_NAME, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-根据策略名称，获取相应的证书错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-根据策略名称，获取相应的证书错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * <p>获取证书信息</p>
     * <p>获取用户指定的证书信息内容</p>
     *
     * @param base64Certificate ：Base64编码的证书文件
     * @param certInfoType      : 用户待获取的证书内容类型 : 类型定义在类 certParseInfoType 中
     * @return ：用户获取到的证书信息内容
     */

    public byte[] getCertInfo(byte[] base64Certificate, int certInfoType) throws AFCryptoException {
        logger.info("SV-获取证书信息,base64Certificate:{},certInfoType:{}", base64Certificate, certInfoType);
        byte[] param = new BytesBuffer()
                .append(certInfoType)
                .append(base64Certificate.length)
                .append(base64Certificate)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_INFO, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取证书信息错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取证书信息错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] bytes = res.getDataBuffer().readOneData();
        return new String(bytes).toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);

    }

    /**
     * <p>获取证书扩展信息</p>
     * <p>获取用户指定的证书扩展信息内容</p>
     *
     * @param certData ：Base64编码的证书文件
     * @param oid       : 用户待获取的证书内容类型OID值 : OID值定义在类 certParseInfoType 中
     * @return ：用户获取到的证书信息内容
     */

    public byte[] getCertInfoByOid(byte[] certData, byte[] oid) throws AFCryptoException {
        logger.info("SV-获取证书扩展信息,certData:{},oid:{}", certData, oid);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(oid.length)
                .append(oid)
                .append(certData.length)
                .append(certData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_EXT_TYPE_INFO, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取证书扩展信息错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取证书扩展信息错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();

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

    public byte[] decodeEnvelopedDataForSM2(int keyIndex, int decodeKeyUsage, byte[] envelopedData) throws AFCryptoException {
        return new byte[0];
    }


}
