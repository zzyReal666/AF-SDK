package com.af.device.cmd;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.constant.ConstantNumber;
import com.af.constant.GroupMode;
import com.af.crypto.struct.impl.signAndVerify.*;
import com.af.device.AFDeviceFactory;
import com.af.device.DeviceInfo;
import com.af.device.impl.AFHsmDevice;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import com.af.utils.SM4Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;

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
        AFHsmDevice device = AFDeviceFactory.getAFHsmDevice(this.client.getHost(), this.client.getPort(), this.client.getPassword());
        RequestMessage req = new RequestMessage(CMDCode.CMD_VERIFY_CERT, device.SM4Encrypt(GroupMode.ECB, agkey, param, null));
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
        } else {
            return responseMessage.getDataBuffer().readOneData();
        }

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
       // param = SM4Utils.encrypt(param, agkey);
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_INTERNALSIGN_ECC, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM2内部密钥签名失败, 错误码: {}, 错误信息: {}",  responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2内部密钥签名失败");
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    private  void getPrivateAccess(int index) throws AFCryptoException {
        String pwd = "12345678";
        byte[] param = new BytesBuffer()
                .append(index)
                .append(pwd.length())
                .append(pwd.getBytes(StandardCharsets.UTF_8))
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GETPRIVATEKEYACCESSRIGHT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取私钥访问权限失败, 错误码: {}, 错误信息: {}",  responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
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

    public byte[] getSm2PublicKey(int keyIndex, int keyUsage) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>查询证书信任列表别名</p>
     * <p>查询证书信任列表别名</p>
     *
     * @return 信任列表别名组合，如： CA001|CA002|CA003
     */

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

    public byte[] getCertByAltName(byte[] altName, int certIndex) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p>获取应用策略</p>
     * <p>根据策略名称获取应用策略，此应用策略为用户在管理程序中创建。用户获取应用策略后，签名服务器会根据用户设定的策略内容进行相关的服务操作</p>
     *
     * @param policyName ：策略名称
     */

    public void getInstance(byte[] policyName) throws AFCryptoException {

    }

    /**
     * <p>删除用户证书列表</p>
     * <p>根据证书别名删除证书列表</p>
     *
     * @param altName ：证书列表别名
     */

    public void deleteCertList(byte[] altName) throws AFCryptoException {

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
