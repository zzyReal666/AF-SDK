package com.af.crypto.algorithm.sm4;

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
 * @since 2023/4/27 14:54
 */
public class SM4Impl implements SM4 {
    private static final Logger logger = LoggerFactory.getLogger(SM4Impl.class);

    private final AFNettyClient client;
    private final KeyInfoImpl keyInfo;
    private final byte[] agKey;

    public SM4Impl(AFNettyClient client, byte[] agKey) {
        this.client = client;
        this.keyInfo = KeyInfoImpl.getInstance(client, agKey);
        this.agKey = agKey;
    }

    /**
     * SM4 ECB模式加密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] encrypt(int index, byte[] data) throws AFCryptoException {
        int zero = 0;
        byte[] key = keyInfo.exportSymmKey(index);
        int keyType = 0;
        int keyId = 0;
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_ECB)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(zero)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_ENCRYPT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM4 ECB 加密错误, 错误信息: {}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM4 ECB 加密错误, 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM4 ECB模式加密 使用外部部密钥
     *
     * @param key  外部密钥
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] encrypt(byte[] key, byte[] data) throws AFCryptoException {
        int zero = 0;
        int keyType = 0;
        int keyId = 0;

        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_ECB)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(zero)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_ENCRYPT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM4 ECB 加密错误, 错误信息: {}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM4 ECB 加密错误, 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM4 ECB模式解密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] decrypt(int index, byte[] data) throws AFCryptoException {
        byte[] key = keyInfo.exportSymmKey(index);
        int zero = 0;
        int keyType = 0;
        int keyId = 0;
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_ECB)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(zero)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_DECRYPT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM4 ECB 解密错误, 错误信息: {}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM4 ECB 解密错误, 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM4 ECB模式解密 使用外部密钥
     *
     * @param key  外部密钥
     * @param data 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] decrypt(byte[] key, byte[] data) throws AFCryptoException {
        int zero = 0;
        int keyType = 0;
        int keyId = 0;
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_ECB)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(zero)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_DECRYPT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM4 ECB 解密错误, 错误信息: {}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM4 ECB 解密错误, 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM4 CBC模式加密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待加密数据
     * @param iv    初始向量
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] encrypt(int index, byte[] data, byte[] iv) throws AFCryptoException {
        byte[] key = keyInfo.exportSymmKey(index);
        int keyType = 0;
        int keyId = 0;
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_CBC)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(iv.length)
                .append(iv)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_ENCRYPT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM4 CBC 加密错误, 错误信息: {}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM4 CBC 加密错误, 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * SM4 CBC模式加密 使用外部密钥
     *
     * @param key  外部密钥
     * @param data 待加密数据
     * @param iv   初始向量
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public byte[] encrypt(byte[] key, byte[] data, byte[] iv) throws AFCryptoException {

        int keyType = 0;
        int keyId = 0;
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_CBC)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(iv.length)
                .append(iv)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_ENCRYPT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM4 CBC 加密错误, 错误信息: {}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM4 CBC 加密错误, 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();

    }

    /**
     * SM4 CBC模式解密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待解密数据
     * @param iv    初始向量
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] decrypt(int index, byte[] data, byte[] iv) throws AFCryptoException {
        byte[] key = keyInfo.exportSymmKey(index);
        int keyType = 0;
        int keyId = 0;
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_CBC)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(iv.length)
                .append(iv)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_DECRYPT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM4 CBC 解密错误, 错误信息: {}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM4 CBC 解密错误, 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        int dataLen = BytesOperate.bytes2int(responseMessage.getData());
        return BytesOperate.subBytes(responseMessage.getData(), 4, dataLen);
    }

    /**
     * SM4 CBC模式解密 使用外部密钥
     *
     * @param key  外部密钥
     * @param data 待解密数据
     * @param iv   初始向量
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] decrypt(byte[] key, byte[] data, byte[] iv) throws AFCryptoException {
        int keyType = 0;
        int keyId = 0;
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_CBC)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(iv.length)
                .append(iv)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_DECRYPT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SM4 CBC 解密错误, 错误信息: {}", responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SM4 CBC 解密错误, 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        int dataLen = BytesOperate.bytes2int(responseMessage.getData());
        return BytesOperate.subBytes(responseMessage.getData(), 4, dataLen);
    }

    /**
     * SM4  MAC计算 使用内部密钥
     *
     * @param index 密钥索引
     * @param data  待计算MAC的数据
     * @param IV    初始向量
     * @return MAC
     * @throws AFCryptoException 计算MAC异常
     */
    @Override
    public byte[] SM4Mac(int index, byte[] data, byte[] IV) throws AFCryptoException {
        int keyType = 0;
        int keyId = 0;
        byte[] key = keyInfo.exportSymmKey(index);
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_CBC)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(IV.length)
                .append(IV)
                .append(data.length)
                .append(data)
                .toBytes();

        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_CALCULATEMAC, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("SM4 Mac error,ErrorInfo:{}" + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();

    }

    /**
     * SM4  MAC计算 使用外部密钥
     *
     * @param key  密钥
     * @param data 待计算MAC的数据
     * @param IV   初始向量
     * @return MAC
     * @throws AFCryptoException 计算MAC异常
     */
    @Override
    public byte[] SM4Mac(byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        int keyType = 0;
        int keyId = 0;
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_SMS4_CBC)
                .append(keyType)
                .append(keyId)
                .append(key.length)
                .append(key)
                .append(IV.length)
                .append(IV)
                .append(data.length)
                .append(data)
                .toBytes();

        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_CALCULATEMAC, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("SM4 Mac error,ErrorInfo:{}" + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

}
