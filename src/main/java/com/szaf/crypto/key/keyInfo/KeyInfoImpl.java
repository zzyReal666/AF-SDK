package com.szaf.crypto.key.keyInfo;

import com.szaf.bean.RequestMessage;
import com.szaf.bean.ResponseMessage;
import com.szaf.constant.CMDCode;
import com.szaf.exception.AFCryptoException;
import com.szaf.netty.AFNettyClient;
import com.szaf.utils.BytesBuffer;
import com.szaf.constant.CmdConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/6 10:02
 */
public class KeyInfoImpl implements KeyInfo {
    private static final Logger logger = LoggerFactory.getLogger(KeyInfoImpl.class);

    private final AFNettyClient client;
    private static KeyInfoImpl instance = null;
    private final byte[] agKey;

    private KeyInfoImpl(AFNettyClient client,byte[] agKey) {
        this.client = client;
        this.agKey = agKey;
    }

    public static KeyInfoImpl getInstance(AFNettyClient client,byte[] agKey) {
        if (instance == null) {
            instance = new KeyInfoImpl(client,agKey);
        }
        return instance;
    }


    /**
     * 获取私钥访问权限
     *
     * @param keyIndex 密钥索引
     * @param keyType  密钥类型 4:RSA; 3:SM2;
     * @param passwd   私钥访问权限口令
     * @return 0:成功; 非0:失败
     * @throws AFCryptoException 获取私钥访问权限异常
     */
    @Override
    public int getPrivateKeyAccessRight(int keyIndex, int keyType, byte[] passwd) throws AFCryptoException {
        logger.info("获取私钥访问权限");
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(keyType)
                .append(passwd.length)
                .append(passwd)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GET_PRIVATE_KEY_ACCESS_RIGHT, param,agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取私钥访问权限异常,错误码:{},错误信息:{}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取私钥访问权限异常,错误码:" + responseMessage.getHeader().getErrorCode() + ",错误信息:" + responseMessage.getHeader().getErrorInfo());
        } else {
            return 0;
        }
    }


    @Override
    public byte[] exportSymmKey(int index) throws AFCryptoException {
        logger.info("exportSymKey,index:{}", index);
        RequestMessage req = new RequestMessage(CmdConsts.CMD_EXPORT_KEY, new BytesBuffer().append(index).toBytes(),agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("exportSymKey 失败,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("exportSymKey 失败,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }
}
