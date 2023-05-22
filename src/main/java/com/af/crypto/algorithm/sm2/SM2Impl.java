package com.af.crypto.algorithm.sm2;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.constant.ConstantNumber;
import com.af.constant.SM2KeyType;
import com.af.crypto.algorithm.sm3.SM3;
import com.af.crypto.algorithm.sm3.SM3Impl;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.crypto.struct.impl.sm2.SM2Cipher;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/5 15:02
 */
public class SM2Impl implements SM2 {

    private static final Logger logger = LoggerFactory.getLogger(SM2Impl.class);
    private final AFNettyClient client;
    private final SM3 sm3;

    public SM2Impl(AFNettyClient client) {
        this.client = client;
        this.sm3 = new SM3Impl(client);
    }

    /**
     * 获取SM2公钥
     *
     * @param index 密钥索引
     * @param type  密钥类型 签名/加密
     * @return SM2公钥
     * @throws AFCryptoException 获取SM2公钥异常
     */
    @Override
    public SM2PublicKey getPublicKey(int index, SM2KeyType type) throws AFCryptoException {
        BytesBuffer buffer = new BytesBuffer();
        byte[] param = buffer.append(index).append(type.equals(SM2KeyType.SIGN) ?
                ConstantNumber.SGD_SM2_1
                : ConstantNumber.SGD_SM2_2).toBytes();

        RequestMessage requestMessage = new RequestMessage(type.equals(SM2KeyType.SIGN) ?
                CMDCode.CMD_EXPORTSIGNPUBLICKEY_ECC
                : CMDCode.CMD_EXPORTENCPUBLICKEY_ECC, param);

        ResponseMessage responseMessage = client.send(requestMessage);
        logger.debug("获取SM2公钥 responseMessage:{}", responseMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取公钥错误,错误信息:{}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取公钥错误,错误信息:" + responseMessage.getHeader().getErrorInfo());
        }
        int dataLength = BytesOperate.bytes2int(responseMessage.getData());
        byte[] outData = BytesOperate.subBytes(responseMessage.getData(), 4, dataLength);
        return new SM2PublicKey(outData);
    }

    /**
     * 生成SM2密钥对
     *
     * @return SM2密钥对
     * @throws AFCryptoException 生成SM2密钥对异常
     */
    @Override
    public SM2KeyPair generateKeyPair() throws AFCryptoException {
        int keyBits = 256;
        BytesBuffer buffer = new BytesBuffer();
        byte[] param = buffer
                .append(ConstantNumber.SGD_SM2)
                .append(keyBits)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GENERATEKEYPAIR_ECC, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        logger.debug("生成SM2密钥对 responseMessage:{}", responseMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("生成SM2密钥对错误,错误信息:{}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("生成SM2密钥对错误,错误信息:" + responseMessage.getHeader().getErrorInfo());
        }
        int pubKeyLen = BytesOperate.bytes2int(responseMessage.getData());
        byte[] pubKeyData = BytesOperate.subBytes(responseMessage.getData(), 4, pubKeyLen);

        int priKeyLen = BytesOperate.bytes2int(BytesOperate.subBytes(responseMessage.getData(), 4 + pubKeyLen, 4));
        byte[] priKeyData = BytesOperate.subBytes(responseMessage.getData(), 8 + pubKeyLen, priKeyLen);

        return new SM2KeyPair(512, new SM2PublicKey(pubKeyData), new SM2PrivateKey(priKeyData));
    }

    /**
     * SM2加密
     *
     * @param index     内部密钥索引  如果使用外部密钥此参数传-1
     * @param publicKey 外部密钥 如果使用内部密钥此参数传null
     * @param data      待加密数据
     * @return 加密后的数据 SM2Cipher 512位 需要256位调用{@link SM2Cipher#to256()}
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] sm2Encrypt(int index, SM2PublicKey publicKey, byte[] data) throws AFCryptoException {
        int Zero = 0;
        byte[] param;
        if (null != publicKey) {  //使用外部密钥
            param = new BytesBuffer()
                    .append(Zero)
                    .append(ConstantNumber.SGD_SM2_3)
                    .append(Zero)
                    .append(publicKey.size())
                    .append(publicKey.encode())
                    .append(data.length)
                    .append(data)
                    .toBytes();
        } else {  //使用内部密钥
            param = new BytesBuffer()
                    .append(index)
                    .append(ConstantNumber.SGD_SM2_3)
                    .append(Zero)
                    .append(Zero)
                    .append(data.length)
                    .append(data)
                    .toBytes();
        }
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_EXTERNALENCRYPT_ECC, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM2加密错误,错误信息:{}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2加密错误,错误信息:" + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();

    }

    /**
     * SM2解密
     *
     * @param index      内部密钥索引
     * @param privateKey 外部密钥
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM2Decrypt(int index, SM2PrivateKey privateKey, SM2Cipher encodeData) throws AFCryptoException {
        int Zero = 0;
        byte[] param;
        if (null != privateKey) {  // 使用外部密钥
            param = new BytesBuffer()
                    .append(Zero)
                    .append(ConstantNumber.SGD_SM2_3)
                    .append(Zero)
                    .append(privateKey.size())
                    .append(privateKey.encode())
                    .append(encodeData.size())
                    .append(encodeData.encode())
                    .toBytes();
        } else {       //使用内部密钥
            param = new BytesBuffer()
                    .append(index)
                    .append(ConstantNumber.SGD_SM2_3)
                    .append(Zero)
                    .append(Zero)
                    .append(encodeData.size())
                    .append(encodeData.encode())
                    .toBytes();
        }
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_EXTERNALDECRYPT_ECC, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM2解密错误,错误信息:{}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2解密错误,错误信息:" + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM2签名
     *
     * @param index      内部密钥索引  如果使用外部密钥此参数传-1
     * @param privateKey 外部密钥 如果使用内部密钥此参数传null
     * @param data       待签名数据
     * @return 签名后的数据
     * @throws AFCryptoException 签名异常
     */
    @Override
    public byte[] SM2Sign(int index, SM2PrivateKey privateKey, byte[] data) throws AFCryptoException {
        int begin = 1;
        int zero = 0;
        byte[] hashData = sm3.SM3Hash(data);
        byte[] param;
        RequestMessage requestMessage;
        if (null == privateKey) {   //使用内部密钥
            param = new BytesBuffer()
                    .append(begin)
                    .append(index)
                    .append(hashData.length)
                    .append(hashData)
                    .toBytes();
            requestMessage = new RequestMessage(CMDCode.CMD_INTERNALSIGN_ECC, param);
        } else {   //使用外部密钥
            param = new BytesBuffer()
                    .append(zero)
                    .append(ConstantNumber.SGD_SM2_1)
                    .append(zero)
                    .append(privateKey.size())
                    .append(privateKey.encode())
                    .append(hashData.length)
                    .append(hashData)
                    .toBytes();
            requestMessage = new RequestMessage(CMDCode.CMD_EXTERNALSIGN_ECC, param);
        }
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM2签名错误,错误信息:{}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM2签名错误,错误信息:" + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM2验签
     *
     * @param index     内部密钥索引  如果使用外部密钥此参数传-1
     * @param publicKey 外部密钥 如果使用内部密钥此参数传null
     * @param data      待验签数据
     * @param signData  签名数据
     * @return 验签结果
     * @throws AFCryptoException 验签异常
     */
    @Override
    public boolean SM2Verify(int index, SM2PublicKey publicKey, byte[] data, byte[] signData) throws AFCryptoException {
        int begin = 1;
        int zero = 0;
        byte[] hashData = sm3.SM3Hash(data);
        byte[] param;
        RequestMessage requestMessage;
        if (null == publicKey) {
            param = new BytesBuffer()
                    .append(begin)
                    .append(index)
                    .append(hashData.length)
                    .append(hashData)
                    .append(signData.length)
                    .append(signData)
                    .toBytes();
            requestMessage = new RequestMessage(CMDCode.CMD_INTERNALVERIFY_ECC, param);
        } else {
            param = new BytesBuffer()
                    .append(zero)
                    .append(ConstantNumber.SGD_SM2_1)
                    .append(zero)
                    .append(publicKey.size())
                    .append(publicKey.encode())
                    .append(hashData.length)
                    .append(hashData)
                    .append(signData.length)
                    .append(signData)
                    .toBytes();
            requestMessage = new RequestMessage(CMDCode.CMD_EXTERNALVERIFY_ECC, param);
        }

        ResponseMessage responseMessage = client.send(requestMessage);
        return responseMessage.getHeader().getErrorCode() == 0;
    }
}
