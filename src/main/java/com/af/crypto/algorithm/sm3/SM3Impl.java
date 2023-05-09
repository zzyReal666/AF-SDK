package com.af.crypto.algorithm.sm3;

import com.af.crypto.key.sm2.SM2PubKey;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/5 15:02
 */
public class SM3Impl implements SM3{


    private final AFNettyClient client;

    public SM3Impl(AFNettyClient client) {
        this.client = client;
    }


    /**
     * SM3 hash
     *
     * @param data
     * @return
     * @throws AFCryptoException
     */
    @Override
    public byte[] SM3Hash(byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM3 hash with userID
     *
     * @param data      待hash数据
     * @param publicKey 公钥 256/512
     * @param userID    用户ID
     * @return hash结果
     * @throws AFCryptoException hash异常
     */
    @Override
    public byte[] SM3HashWithPublicKey256(byte[] data, SM2PubKey publicKey, byte[] userID) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM3 HMAC
     *
     * @param index 内部密钥索引  如果使用外部密钥，此参数传-1
     * @param key   外部密钥 如果使用内部密钥，此参数传null
     * @param data  待hash数据
     * @return hash结果
     * @throws AFCryptoException hash异常
     */
    @Override
    public byte[] SM3HMac(int index, byte[] key, byte[] data) throws AFCryptoException {
        return new byte[0];
    }
}
