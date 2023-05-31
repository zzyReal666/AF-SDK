package com.af.crypto.algorithm.sm4;

import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 国密SM4算法接口 用于加解密 MAC计算
 * @since 2023/4/24 15:09
 */
public interface SM4 {

    //===================ECB模式加解密相关===================

    /**
     * SM4 ECB模式加密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    byte[] encrypt(int index, byte[] data) throws AFCryptoException;

    /**
     * SM4 ECB模式加密 使用外部部密钥
     *
     * @param key  外部密钥
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    byte[] encrypt(byte[] key, byte[] data) throws AFCryptoException;


    /**
     * SM4 ECB模式解密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] decrypt(int index, byte[] data) throws AFCryptoException;

    /**
     * SM4 ECB模式解密 使用外部密钥
     *
     * @param key  外部密钥
     * @param data 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] decrypt(byte[] key, byte[] data) throws AFCryptoException;

    //===================CBC模式加解密相关===================

    /**
     * SM4 CBC模式加密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待加密数据
     * @param iv    初始向量
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    byte[] encrypt(int index, byte[] data, byte[] iv) throws AFCryptoException;

    /**
     * SM4 CBC模式加密 使用外部密钥
     *
     * @param key  外部密钥
     * @param data 待加密数据
     * @param iv   初始向量
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    byte[] encrypt(byte[] key, byte[] data, byte[] iv) throws AFCryptoException;

    /**
     * SM4 CBC模式解密 使用内部密钥
     *
     * @param index 内部密钥索引
     * @param data  待解密数据
     * @param iv    初始向量
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] decrypt(int index, byte[] data, byte[] iv) throws AFCryptoException;

    /**
     * SM4 CBC模式解密 使用外部密钥
     *
     * @param key  外部密钥
     * @param data 待解密数据
     * @param iv   初始向量
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] decrypt(byte[] key, byte[] data, byte[] iv) throws AFCryptoException;


    //===================MAC计算相关===================

    /**
     * SM4  MAC计算 使用内部密钥
     *
     * @param index 密钥索引
     * @param data  待计算MAC的数据
     * @param IV    初始向量
     * @return MAC
     * @throws AFCryptoException 计算MAC异常
     */
    byte[] SM4Mac(int index, byte[] data, byte[] IV) throws AFCryptoException;

    /**
     * SM4  MAC计算 使用外部密钥
     *
     * @param key  密钥
     * @param data 待计算MAC的数据
     * @param IV   初始向量
     * @return MAC
     * @throws AFCryptoException 计算MAC异常
     */
    byte[] SM4Mac(byte[] key, byte[] data, byte[] IV) throws AFCryptoException;



}
