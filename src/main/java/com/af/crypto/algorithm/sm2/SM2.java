package com.af.crypto.algorithm.sm2;

import com.af.constant.SM2KeyType;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.struct.impl.sm2.SM2Cipher;
import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description SM2算法接口
 * @since 2023/4/26 10:43
 */
public interface SM2 {

    //===================获取密钥相关===================


    /**
     * 获取SM2公钥
     *
     * @param index  密钥索引
     * @param type   密钥类型 签名/加密
     * @return SM2公钥
     * @throws AFCryptoException 获取SM2公钥异常
     */
    SM2PublicKey getPublicKey(int index, SM2KeyType type) throws AFCryptoException;




    //===================生成密钥相关===================

    /**
     * 生成SM2密钥对
     *
     * @return SM2密钥对
     * @throws AFCryptoException 生成SM2密钥对异常
     */
    SM2KeyPair generateKeyPair() throws AFCryptoException;


    //===================加密解密相关===================

    /**
     * SM2加密
     *
     * @param index     内部密钥索引  如果使用外部密钥此参数传-1
     * @param publicKey 外部密钥 如果使用内部密钥此参数传null
     * @param data      待加密数据
     * @return 加密后的数据 SM2Cipher 512位 需要256位调用{@link SM2Cipher#to256()}
     * @throws AFCryptoException 加密异常
     */
    byte[] sm2Encrypt(int index, SM2PublicKey publicKey, byte[] data) throws AFCryptoException;

    /**
     * SM2解密
     *
     * @param index      内部密钥索引  如果使用外部密钥此参数传-1
     * @param publicKey  外部密钥 如果使用内部密钥此参数传null
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] SM2Decrypt(int index, SM2PrivateKey privateKey, SM2Cipher encodeData) throws AFCryptoException;
    //===================签名验签相关===================


    /**
     * SM2签名
     *
     * @param index      内部密钥索引  如果使用外部密钥此参数传-1
     * @param privateKey 外部密钥 如果使用内部密钥此参数传null
     * @param data       待签名数据
     * @return 签名后的数据
     * @throws AFCryptoException 签名异常
     */
    byte[] SM2Sign(int index, SM2PrivateKey privateKey, byte[] data) throws AFCryptoException;

    /**
     * SM2验签
     *
     * @param index     内部密钥索引  如果使用外部密钥此参数传-1
     * @param publicKey 外部密钥 如果使用内部密钥此参数传null
     * @param data      待验签数据
     * @param signData  签名数据
     * @return 验签结果
     * @throws AFCryptoException 验签异常
     */
    boolean SM2Verify(int index, SM2PublicKey publicKey, byte[] data, byte[] signData) throws AFCryptoException;

}
