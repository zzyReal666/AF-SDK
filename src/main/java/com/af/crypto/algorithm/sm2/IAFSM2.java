package com.af.crypto.algorithm.sm2;

import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.constant.SM2KeyType;
import com.af.crypto.key.sm2.SM2PubKey;
import com.af.crypto.struct.impl.SM2Cipher;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description SM2算法接口
 * @since 2023/4/26 10:43
 */
public interface IAFSM2 {

    //===================获取密钥相关===================


    /**
     * 获取SM2公钥
     *
     * @param index  密钥索引
     * @param length 密钥长度 256/512
     * @param type   密钥类型 签名/加密
     * @return SM2公钥
     * @throws Exception 获取SM2公钥异常
     */
    SM2PubKey getPublicKey(int index, int length, SM2KeyType type) throws Exception;


    //===================生成密钥相关===================

    /**
     * 生成SM2密钥对
     *
     * @param length 密钥长度 256/512
     * @return SM2密钥对
     * @throws Exception 生成SM2密钥对异常
     */
    SM2KeyPair generateKeyPair(int length) throws Exception;


    //===================加密解密相关===================
    SM2Cipher sm2Encrypt(int index, byte[] data) throws Exception;


    //===================签名验签相关===================
}
