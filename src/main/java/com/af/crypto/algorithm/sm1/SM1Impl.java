package com.af.crypto.algorithm.sm1;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.constant.ConstantNumber;
import com.af.crypto.key.keyInfo.KeyInfoImpl;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/5 15:01
 */
public class SM1Impl implements SM1 {

    private static final Logger logger = LoggerFactory.getLogger(SM1Impl.class);
    private final KeyInfoImpl keyInfo;
    private final AFNettyClient client;

    public SM1Impl(AFNettyClient client) {
        this.client = client;
        this.keyInfo = KeyInfoImpl.getInstance(client);
    }


    /**
     * SM1 ECB模式加密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] SM1EncryptECB(int index, byte[] data) throws AFCryptoException {
        logger.info("SM1EncryptECB");
        BytesBuffer buffer = new BytesBuffer();
        byte[] key = keyInfo.exportSymmKey(index);
        int keyType = 0;
        int keyID = 0;
        int zero = 0;
        byte[] param = buffer.append(ConstantNumber.SGD_SM1_ECB)
                .append(keyType)
                .append(keyID)
                .append(key.length)
                .append(key)

                .append(zero)

                .append(data.length)
                .append(data).toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_ENCRYPT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM1EncryptECB failed, ErrorCode: {} ,ErrorInfo: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM1EncryptECB failed, ErrorInfo: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    @Override
    public byte[] SM1EncryptECB(byte[] key, byte[] data) throws AFCryptoException {
        logger.info("SM1EncryptECB");
        BytesBuffer buffer = new BytesBuffer();
        int keyType = 0;
        int keyID = 0;
        int zero = 0;
        byte[] param = buffer.append(ConstantNumber.SGD_SM1_ECB)
                .append(keyType)
                .append(keyID)
                .append(key.length)
                .append(key)

                .append(zero)

                .append(data.length)
                .append(data).toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_ENCRYPT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM1EncryptECB failed, ErrorCode: {} ,ErrorInfo: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM1EncryptECB failed, ErrorInfo: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM1 ECB模式解密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM1DecryptECB(int index, byte[] data) throws AFCryptoException {
        logger.info("SM1DecryptECB");
        BytesBuffer buffer = new BytesBuffer();
        byte[] key = keyInfo.exportSymmKey(index);
        int keyType = 0;
        int keyID = 0;
        int zero = 0;
        byte[] param = buffer.append(ConstantNumber.SGD_SM1_ECB)
                .append(keyType)
                .append(keyID)
                .append(key.length)
                .append(key)

                .append(zero)

                .append(data.length)
                .append(data).toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_DECRYPT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("SM1DecryptECB failed, ErrorInfo: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM1 ECB模式解密 使用外部密钥
     *
     * @param key        外部密钥
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM1DecryptECB(byte[] key, byte[] encodeData) throws AFCryptoException {
        logger.info("SM1DecryptECB");
        BytesBuffer buffer = new BytesBuffer();
        int keyType = 0;
        int keyID = 0;
        int zero = 0;
        byte[] param = buffer.append(ConstantNumber.SGD_SM1_ECB)
                .append(keyType)
                .append(keyID)
                .append(key.length)
                .append(key)

                .append(zero)

                .append(encodeData.length)
                .append(encodeData).toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_DECRYPT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("SM1DecryptECB failed, ErrorInfo: " + responseMessage.getHeader().getErrorInfo());
        }
        int dataLen = BytesOperate.bytes2int(responseMessage.getData());
        return BytesOperate.subBytes(responseMessage.getData(), 4, dataLen);
    }

    /**
     * SM1 CBC模式加密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param iv    初始化向量
     * @param data  待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] SM1EncryptCBC(int index, byte[] iv, byte[] data) throws AFCryptoException {
        logger.info("SM1EncryptCBC");
        BytesBuffer buffer = new BytesBuffer();
        byte[] key = keyInfo.exportSymmKey(index);
        int keyType = 0;
        int keyID = 0;

        byte[] param = buffer.append(ConstantNumber.SGD_SM1_CBC)
                .append(keyType)
                .append(keyID)
                .append(key.length)
                .append(key)

                .append(iv.length)
                .append(iv)

                .append(data.length)
                .append(data).toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_ENCRYPT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("SM1EncryptCBC failed, ErrorInfo: " + responseMessage.getHeader().getErrorInfo());
        }
        int dataLen = BytesOperate.bytes2int(responseMessage.getData());
        byte[] outData = BytesOperate.subBytes(responseMessage.getData(), 4, dataLen);
        byte[] outIV = BytesOperate.subBytes(responseMessage.getData(), dataLen - 16, 16);
        return outData;
    }

    /**
     * SM1 CBC模式加密 使用外部密钥
     *
     * @param key  外部密钥
     * @param iv   初始化向量
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] SM1EncryptCBC(byte[] key, byte[] iv, byte[] data) throws AFCryptoException {
        logger.info("SM1EncryptCBC");
        BytesBuffer buffer = new BytesBuffer();
        int keyType = 0;
        int keyID = 0;
        byte[] param = buffer.append(ConstantNumber.SGD_SM1_CBC)
                .append(keyType)
                .append(keyID)
                .append(key.length)
                .append(key)

                .append(iv.length)
                .append(iv)

                .append(data.length)
                .append(data).toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_ENCRYPT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("SM1EncryptCBC failed, ErrorInfo: " + responseMessage.getHeader().getErrorInfo());
        }
        int dataLen = BytesOperate.bytes2int(responseMessage.getData());
        byte[] outData = BytesOperate.subBytes(responseMessage.getData(), 4, dataLen);
        byte[] outIV = BytesOperate.subBytes(responseMessage.getData(), dataLen - 16, 16);
        return outData;
    }

    /**
     * SM1 CBC模式解密 使用内部密钥
     *
     * @param index      内部密钥索引
     * @param iv         初始向量
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM1DecryptCBC(int index, byte[] iv, byte[] encodeData) throws AFCryptoException {
        logger.info("SM1DecryptCBC");
        BytesBuffer buffer = new BytesBuffer();
        byte[] key = keyInfo.exportSymmKey(index);
        int keyType = 0;
        int keyID = 0;
        byte[] param = buffer.append(ConstantNumber.SGD_SM1_CBC)
                .append(keyType)
                .append(keyID)
                .append(key.length)
                .append(key)

                .append(iv.length)
                .append(iv)

                .append(encodeData.length)
                .append(encodeData).toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_DECRYPT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("SM1DecryptCBC failed, ErrorInfo: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();

    }

    /**
     * SM1 CBC模式解密 使用外部密钥
     *
     * @param key        外部密钥
     * @param iv         初始向量
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM1DecryptCBC(byte[] key, byte[] iv, byte[] encodeData) throws AFCryptoException {
        logger.info("SM1DecryptCBC");
        BytesBuffer buffer = new BytesBuffer();
        int keyType = 0;
        int keyID = 0;
        byte[] param = buffer.append(ConstantNumber.SGD_SM1_CBC)
                .append(keyType)
                .append(keyID)
                .append(key.length)
                .append(key)

                .append(iv.length)
                .append(iv)

                .append(encodeData.length)
                .append(encodeData).toBytes();

        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_DECRYPT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("SM1DecryptCBC failed, ErrorInfo: " + responseMessage.getHeader().getErrorInfo());
        }
        int dataLen = BytesOperate.bytes2int(responseMessage.getData());
        byte[] outData = BytesOperate.subBytes(responseMessage.getData(), 4, dataLen);
        byte[] outIV = BytesOperate.subBytes(responseMessage.getData(), dataLen - 16, 16);
        return outData;
    }
}
