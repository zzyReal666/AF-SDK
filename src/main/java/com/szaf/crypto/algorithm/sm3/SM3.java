package com.szaf.crypto.algorithm.sm3;

import com.szaf.crypto.key.sm2.SM2PublicKey;
import com.szaf.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/27 15:06
 */
public interface SM3 {

    /**
     * SM3 hash
     * @param data
     * @return
     * @throws AFCryptoException
     */
    byte[] SM3Hash(byte[] data) throws AFCryptoException;

    /**
     * SM3 hash with userID
     * @param data 待hash数据
     * @param publicKey 公钥 256/512
     * @param userID 用户ID
     * @return hash结果
     * @throws AFCryptoException hash异常
     */
    byte[] SM3HashWithPublicKey256(byte[] data, SM2PublicKey publicKey, byte[] userID) throws AFCryptoException;




}
