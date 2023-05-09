package com.af.crypto.algorithm.sm4;

import com.af.crypto.key.keyInfo.KeyInfoImpl;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/27 14:54
 */
public class SM4Impl implements SM4 {



    private final AFNettyClient client;
    private final KeyInfoImpl keyInfo;

    public SM4Impl(AFNettyClient client) {
        this.client = client;
        this.keyInfo = KeyInfoImpl.getInstance(client);
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
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
        return new byte[0];
    }

    /**
     * SM4  padding填充
     *
     * @param data 待填充数据
     * @return 填充后的数据
     */
    @Override
    public byte[] padding(byte[] data) {
        return new byte[0];
    }
}
