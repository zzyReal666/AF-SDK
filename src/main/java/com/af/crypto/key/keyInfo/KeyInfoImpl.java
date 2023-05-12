package com.af.crypto.key.keyInfo;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.utils.BytesBuffer;

import java.util.List;

import static com.af.constant.CmdConsts.CMD_EXPORT_KEY;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/6 10:02
 */
public class KeyInfoImpl implements KeyInfo {


    private final AFNettyClient client;
    private static KeyInfoImpl instance = null;

    private KeyInfoImpl(AFNettyClient client) {
        this.client = client;
    }

    public static KeyInfoImpl getInstance(AFNettyClient client) {
        if (instance == null) {
            instance = new KeyInfoImpl(client);
        }
        return instance;
    }




    /**
     * 获取私钥访问权限
     *
     * @param keyIndex 密钥索引
     * @param keyType  密钥类型 1:RSA; 0:SM2;
     * @param passwd   私钥访问权限口令
     * @return 0:成功; 非0:失败
     * @throws AFCryptoException 获取私钥访问权限异常
     */
    @Override
    public int getPrivateKeyAccessRight(int keyIndex, int keyType, byte[] passwd) throws AFCryptoException {
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(keyType)
                .append(passwd.length)
                .append(passwd)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GET_PRIVATE_KEY_ACCESS_RIGHT, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            throw new AFCryptoException("获取私钥访问权限异常");
        }else {
            return 0;
        }
    }

    /**
     * 获取设备内部对称密钥状态
     *
     * @return 设备内部对称密钥状态
     * @throws AFCryptoException 获取设备内部对称密钥状态异常
     */
    @Override
    public List<AFSymmetricKeyStatus> getSymmetricKeyStatus(byte[] agreementKey ) throws AFCryptoException {
        return null;
    }

    /**
     * 导入非易失对称密钥
     *
     * @param index   密钥索引
     * @param keyData 密钥数据(16进制编码)
     * @throws AFCryptoException 导入非易失对称密钥异常
     */
    @Override
    public void importKek(int index, byte[] keyData) throws AFCryptoException {

    }

    /**
     * 销毁非易失对称密钥
     *
     * @param index 密钥索引
     * @throws AFCryptoException 销毁非易失对称密钥异常
     */
    @Override
    public void delKek(int index) throws AFCryptoException {

    }

    /**
     * 生成密钥信息
     *
     * @param keyType 密钥类型 1:对称密钥; 3:SM2密钥 4:RSA密钥;
     * @param keyBits 密钥长度 128/256/512/1024/2048/4096
     * @param count   密钥数量
     * @return 密钥信息列表
     * @throws AFCryptoException 生成密钥信息异常
     */
    @Override
    public List<AFKmsKeyInfo> generateKey(int keyType, int keyBits, int count) throws AFCryptoException {
        return null;
    }


    @Override
    public byte[] exportSymmKey(int index)  {
        RequestMessage req = new RequestMessage(CMD_EXPORT_KEY, new BytesBuffer().append(index).toBytes());
        ResponseMessage res = client.send(req);
        return res.getDataBuffer().readOneData();
    }
}
