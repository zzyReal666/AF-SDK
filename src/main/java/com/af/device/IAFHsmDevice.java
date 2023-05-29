package com.af.device;

import com.af.constant.GroupMode;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.impl.sm2.SM2Cipher;
import com.af.struct.impl.sm2.SM2Signature;
import com.af.exception.AFCryptoException;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description  HSM设备接口
 * @since 2023/5/16 9:16
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
    byte[] sm1Encrypt(GroupMode mode, int index, byte[] iv, byte[] data) throws AFCryptoException;

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
    byte[] sm1Decrypt(GroupMode mode, int index, byte[] iv, byte[] encodeData) throws AFCryptoException;


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
    byte[] sm1Encrypt(GroupMode mode, byte[] key, byte[] iv, byte[] data) throws AFCryptoException;

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
    byte[] sm1Decrypt(GroupMode mode, byte[] key, byte[] iv, byte[] encodeData) throws AFCryptoException;


    //=======================================================SM2===========================================================

    //===================1.密钥相关===================

    /**
     * 获取SM2签名公钥
     *
     * @param index  索引
     * @param length 密钥长度 256/512
     * @return SM2签名公钥
     * @throws AFCryptoException 获取SM2签名公钥异常
     */
    SM2PublicKey getSM2SignPublicKey(int index, ModulusLength length) throws AFCryptoException;

    /**
     * 获取SM2加密公钥
     *
     * @param index 索引
     * @return SM2加密公钥 默认512位, 如果需要256位, 请调用{@link SM2PublicKey#to256()}
     * @throws AFCryptoException 获取SM2加密公钥异常
     */
    SM2PublicKey getSM2EncryptPublicKey(int index, ModulusLength length) throws AFCryptoException;


    /**
     * 生成SM2密钥对
     *
     * @throws AFCryptoException 生成SM2密钥对异常
     */
    SM2KeyPair generateSM2KeyPair(ModulusLength length) throws AFCryptoException;


    //===================2.SM2加解密===================
    //===================2.1内部密钥加解密===================

    /**
     * SM2内部密钥加密
     *
     * @param index 索引
     * @param data  待加密数据
     * @throws AFCryptoException 加密异常
     */
    SM2Cipher sm2Encrypt(ModulusLength length, int index, byte[] data) throws AFCryptoException;

    /**
     * SM2内部密钥解密
     *
     * @param index      索引
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] sm2Decrypt(ModulusLength length, int index, SM2Cipher encodeData) throws AFCryptoException;

    //===================2.2外部密钥加解密===================

    /**
     * SM2外部密钥加密
     *
     * @param key  密钥
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    SM2Cipher sm2Encrypt(ModulusLength length, SM2PublicKey key, byte[] data) throws AFCryptoException;

    /**
     * SM2外部密钥解密
     *
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    byte[] sm2Decrypt(ModulusLength length, SM2PrivateKey privateKey, SM2Cipher encodeData) throws AFCryptoException;


    //===================================SM2签名验签===================================

    /**
     * SM2 内部密钥签名
     *
     * @param index 密钥索引
     * @param data  待签名数据
     * @throws AFCryptoException 签名异常
     */
    SM2Signature sm2Signature(ModulusLength length, int index, byte[] data) throws AFCryptoException;

    /**
     * SM2 内部密钥验签
     *
     * @param index     密钥索引
     * @param data      待验签数据
     * @param signature 签名
     * @return 验签结果 true:验签成功 false:验签失败
     * @throws AFCryptoException 验签异常
     */
    boolean sm2Verify(ModulusLength length, int index, byte[] data, SM2Signature signature) throws AFCryptoException;

    /**
     * SM2 外部密钥签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return 签名
     * @throws AFCryptoException 签名异常
     */
    SM2Signature sm2Signature(ModulusLength length,byte[] data, SM2PrivateKey privateKey) throws AFCryptoException;

    /**
     * SM2 外部密钥验签
     *
     * @param data      待验签数据
     * @param signature 签名
     * @param publicKey 公钥
     * @return 验签结果 true:验签成功 false:验签失败
     * @throws AFCryptoException 验签异常
     */
    boolean sm2Verify(ModulusLength length, byte[] data, SM2Signature signature, SM2PublicKey publicKey) throws AFCryptoException;


    //=======================================================SM3===========================================================


    byte[] sm3Hash(byte[] data) throws AFCryptoException;
    /**
     * SM3哈希 杂凑算法 <br>
     * 带公钥信息和用户ID
     *
     * @param data      待杂凑数据
     * @param publicKey 公钥 可以传入256/512位公钥 实际计算使用256位公钥
     * @param userID    用户ID
     * @return 杂凑值
     * @throws AFCryptoException 杂凑异常
     */
    byte[] sm3HashWithPubKey(byte[] data, SM2PublicKey publicKey, byte[] userID) throws AFCryptoException;
    byte[] SM3HMac(int index, byte[] data) throws AFCryptoException;
    byte[] SM3HMac(byte[] key, byte[] data) throws AFCryptoException;

    //=======================================================SM4===========================================================

    byte[] sm4Mac(int index, byte[] data, byte[] IV) throws AFCryptoException;

    byte[] sm4Mac(byte[] key, byte[] data, byte[] IV) throws AFCryptoException;

    byte[] sm4Encrypt(GroupMode mode, int index, byte[] data, byte[] IV) throws AFCryptoException;

    byte[] sm4Decrypt(GroupMode mode, int index, byte[] data, byte[] IV) throws AFCryptoException;

    byte[] sm4Encrypt(GroupMode mode, byte[] key, byte[] data, byte[] IV) throws AFCryptoException;

    byte[] sm4Decrypt(GroupMode mode, byte[] key, byte[] data, byte[] IV) throws AFCryptoException;




    //=======================================================RSA===========================================================
    /**
     * <p> 获取RSA签名公钥信息 </p>
     *
     * @param index：密钥索引
     * @return 返回RSA签名数据结构
     * @throws AFCryptoException
     */
    RSAPubKey getRSASignPublicKey(int index) throws AFCryptoException;

    /**
     * <p> 获取RSA加密公钥信息 </p>
     *
     * @param index： 密钥索引
     * @return 返回RSA加密数据结构
     * @throws AFCryptoException
     */
    RSAPubKey getRSAEncPublicKey(int index) throws AFCryptoException;

    /**
     * <p> 生成RSA密钥对信息 </p>
     *
     * @param bits: 位长，1024 or 2048
     * @return 返回RSA密钥对数据结构
     * @throws AFCryptoException
     */
    RSAKeyPair generateRSAKeyPair(int bits) throws AFCryptoException;

    /**
     * <p> RSA外部加密运算 </p>
     *
     * @param publicKey ：RSA公钥信息
     * @param data      : 原始数据
     * @return ：返回运算结果
     */
    byte[] RSAExternalEncode(RSAPubKey publicKey, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA外部解密运算 </p>
     *
     * @param prvKey ：RSA私钥信息
     * @param data   : 加密数据
     * @return ：返回运算结果
     */
    byte[] RSAExternalDecode(RSAPriKey prvKey, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA外部签名运算 </p>
     *
     * @param prvKey ：RSA私钥信息
     * @param data   : 原始数据
     * @return ：返回运算结果
     */
    byte[] RSAExternalSign(RSAPriKey prvKey, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA外部验证签名运算 </p>
     *
     * @param publicKey ：RSA公钥信息
     * @param data      : 签名数据
     * @param rawData   : 原始数据
     * @return ：true: 验证成功，false：验证失败
     */
    boolean RSAExternalVerify(RSAPubKey publicKey, byte[] data, byte[] rawData) throws AFCryptoException;

    /**
     * <p> RSA内部加密运算 </p>
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 原始数据
     * @return ：返回运算结果
     */
    byte[] RSAInternalEncode(int index, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA内部解密运算 </p>
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 加密数据
     * @return ：返回运算结果
     */
    byte[] RSAInternalDecode(int index, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA内部签名运算</p>
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 原始数据
     * @return ：返回运算结果
     */
    byte[] RSAInternalSign(int index, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA内部验证签名运算 </p>
     *
     * @param index   ：RSA内部密钥索引
     * @param data    : 签名数据
     * @param rawData : 原始数据
     * @return ：true: 验证成功，false：验证失败
     */
    boolean RSAInternalVerify(int index, byte[] data, byte[] rawData) throws AFCryptoException;

    //================================================others====================================================

    /**
     * 获取私钥访问权限
     *
     * @param keyIndex 密钥索引
     * @param keyType  密钥类型 1:RSA; 0:SM2;
     * @param passwd   私钥访问权限口令
     * @return 0:成功; 非0:失败
     * @throws AFCryptoException 获取私钥访问权限异常
     */
    int getPrivateKeyAccessRight(int keyIndex, int keyType, byte[] passwd) throws AFCryptoException;


//    /**
//     * 获取设备内部对称密钥状态
//     *
//     * @return 设备内部对称密钥状态
//     * @throws AFCryptoException 获取设备内部对称密钥状态异常
//     */
//    List<AFSymmetricKeyStatus> getSymmetricKeyStatus() throws AFCryptoException;
//
//    /**
//     * 导入非易失对称密钥
//     *
//     * @param index   密钥索引
//     * @param keyData 密钥数据(16进制编码)
//     * @throws AFCryptoException 导入非易失对称密钥异常
//     */
//    void importKek(int index, byte[] keyData) throws AFCryptoException;
//
//
//    /**
//     * 销毁非易失对称密钥
//     *
//     * @param index 密钥索引
//     * @throws AFCryptoException 销毁非易失对称密钥异常
//     */
//    void delKek(int index) throws AFCryptoException;
//
//
//    /**
//     * 生成密钥信息
//     *
//     * @param keyType 密钥类型 1:对称密钥; 3:SM2密钥 4:RSA密钥;
//     * @param keyBits 密钥长度 128/256/512/1024/2048/4096
//     * @param count   密钥数量
//     * @return 密钥信息列表
//     * @throws AFCryptoException 生成密钥信息异常
//     */
//    List<AFKmsKeyInfo> generateKey(int keyType, int keyBits, int count) throws AFCryptoException;
}
