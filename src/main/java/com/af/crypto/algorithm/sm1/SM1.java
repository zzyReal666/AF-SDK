package com.af.crypto.algorithm.sm1;

import com.af.constant.GroupMode;
import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/27 15:05
 */
public interface SM1 {
    /**
     * SM1加密
     *
     * @param mode  分组模式 ECB/CBC
     * @param index 内部密钥索引 如果使用外部密钥，此参数无效
     * @param key   外部密钥 如果使用内部密钥，此参数无效
     * @param data  待加密数据
     * @param IV    初始向量 如果使用ECB模式，此参数无效
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    byte[] SM1Encrypt(GroupMode mode, int index, byte[] key, byte[] data, byte[] IV) throws AFCryptoException;

    /**
     * SM1解密
     *
     * @param mode  分组模式 ECB/CBC
     * @param index 内部密钥索引 如果使用外部密钥，此参数无效
     * @param key   外部密钥 如果使用内部密钥，此参数无效
     * @param data  待解密数据
     * @param IV    初始向量 如果使用ECB模式，此参数无效
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] SM1Decrypt(GroupMode mode, int index, byte[] key, byte[] data, byte[] IV) throws AFCryptoException;
}
