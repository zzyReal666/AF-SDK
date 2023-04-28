package com.af.device;

import com.af.constant.GroupMode;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PubKey;
import com.af.crypto.struct.impl.SM2Cipher;
import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description HSM设备接口 : <br/>
 * @SM1 SM1内部密钥加密 {@link com.af.device.IAFHsmDevice#SM1Encrypt(GroupMode, int, byte[], byte[])}<br/>
 * SM1外部密钥加密 {@link com.af.device.IAFHsmDevice#SM1Encrypt(GroupMode, byte[], byte[], byte[])}<br/>
 * @since 2023/4/28 14:31
 */
public interface IAFHsmDevice extends IAFDevice {

    //=======================================================SM1===========================================================


    //==================1.内部密钥加解密==================


    /**
     * SM1内部密钥加密
     *
     * @param mode  分组模式 ECB/CBC
     * @param index 内部密钥索引
     * @param iv    初始向量  CBC模式下需要 ECB模式下传null
     * @param data  待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    byte[] SM1Encrypt(GroupMode mode, int index, byte[] iv, byte[] data) throws AFCryptoException;

    /**
     * SM1内部密钥解密
     *
     * @param mode       分组模式 ECB/CBC
     * @param index      内部密钥索引
     * @param iv         初始向量  CBC模式下需要 ECB模式下传null
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] SM1Decrypt(GroupMode mode, int index, byte[] iv, byte[] encodeData) throws AFCryptoException;


    //==================2.外部密钥加解密==================

    /**
     * SM1外部密钥加密
     *
     * @param mode 分组模式 ECB/CBC
     * @param key  密钥
     * @param iv   初始向量  CBC模式下需要 ECB模式下传null
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    byte[] SM1Encrypt(GroupMode mode, byte[] key, byte[] iv, byte[] data) throws AFCryptoException;

    /**
     * SM1外部密钥解密
     *
     * @param mode       分组模式 ECB/CBC
     * @param key        密钥
     * @param iv         初始向量  CBC模式下需要 ECB模式下传null
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] SM1Decrypt(GroupMode mode, byte[] key, byte[] iv, byte[] encodeData) throws AFCryptoException;


    //=======================================================SM2===========================================================

    //===================1.密钥相关===================

    /**
     * 获取SM2签名公钥
     *
     * @param index 索引
     * @return SM2签名公钥
     * @throws AFCryptoException 获取SM2签名公钥异常
     */
    SM2PubKey getSM2SignPublicKey(int index) throws AFCryptoException;

    /**
     * 获取SM2加密公钥
     *
     * @param index 索引
     * @return SM2加密公钥
     * @throws AFCryptoException 获取SM2加密公钥异常
     */
    SM2PubKey getSM2EncryptPublicKey(int index) throws AFCryptoException;


    /**
     * 生成SM2密钥对
     *
     * @return SM2密钥对 默认512位, 如果需要256位, 请调用{@link com.af.crypto.key.sm2.SM2KeyPair#to256()}
     * @throws AFCryptoException 生成SM2密钥对异常
     */
    SM2KeyPair generateSM2KeyPair() throws AFCryptoException;
    //===================2.SM2加解密===================
    //===================2.1内部密钥加解密===================

    /**
     * SM2内部密钥加密
     *
     * @param length 密钥长度
     * @param index  索引
     * @param data   待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    SM2Cipher SM2Encrypt(ModulusLength length, int index, byte[] data) throws AFCryptoException;

    /**
     * SM2内部密钥解密
     *
     * @param index      索引
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] SM2Decrypt(int index, SM2Cipher encodeData) throws AFCryptoException;

    //===================2.2外部密钥加解密===================

    /**
     * SM2外部密钥加密
     *
     * @param key  密钥
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    SM2Cipher SM2Encrypt(ModulusLength length, byte[] key, byte[] data) throws AFCryptoException;

    /**
     * SM2外部密钥解密
     *
     * @param key        密钥
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] SM2Decrypt(byte[] key, SM2Cipher encodeData) throws AFCryptoException;


    //=======================================================SM3===========================================================


    //=======================================================SM4===========================================================

    //=======================================================内部密钥加解密===================================================

    //=======================================================外部密钥加解密===================================================
}
