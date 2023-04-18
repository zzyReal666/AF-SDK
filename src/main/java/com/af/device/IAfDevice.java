package com.af.device;

import com.af.crypto.key.AFKmsKeyInfo;
import com.af.crypto.key.AFSymmetricKeyStatus;
import com.af.crypto.struct.impl.*;
import com.af.exception.AFCryptoException;

import java.util.List;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description  密码机接口 用于获取密码机的设备信息、随机数、密钥信息等
 * @since 2023/4/18 10:57
 */
public interface IAfDevice {
    /**
     * <p> 获取随机数 </p>
     * <p> 用户获取指定长度的随机数据 </p>
     * @param randomLength : 待取得随机数的长度
     * @return ：返回取得的随机数数据
     * @throws AFCryptoException ：抛出异常
     */
    byte[] generateRandom(int randomLength) throws AFCryptoException;

    /**
     * <p> 获取设备信息 </p>
     * <p> 用户获取密码机的设备信息,查看设备信息时，可使用DeviceInfo中的toString()方法 例如：
     *   System.out.println(instance.getDeviceInfo().toString());
     *  </p>
     * @return ：返回密码机设备信息
     * @throws AFCryptoException
     */
    DeviceInfo getDeviceInfo() throws AFCryptoException;

    /**
     * <p> 获取模长为256的SM2签名公钥信息 </p>
     * <p> 获取模长为256的SM2签名公钥信息，可使用SM2PublicKeyByM256中的toString()方法查看密钥信息 例如：
     *   System.out.println(instance.getSM2SignPublicKey256(1).toString());
     *  </p>
     * @param index ：待获取的加密机内部密钥索引
     * @return ： 返回密码机内部指定索引的签名公钥信息
     * @throws AFCryptoException
     */
    SM2PublicKeyByM256 getSM2SignPublicKey256(int index) throws AFCryptoException;

    /**
     * <p> 获取模长为256的SM2加密公钥信息 </p>
     * <p> 获取模长为256的SM2加密公钥信息，可使用SM2PublicKeyByM256中的toString()方法查看密钥信息 例如：
     *   System.out.println(instance.getSM2EncPublicKey256(1).toString());
     *  </p>
     * @param index ：待获取的加密机内部密钥索引
     * @return ： 返回密码机内部指定索引的加密公钥信息
     * @throws AFCryptoException
     */
    SM2PublicKeyByM256 getSM2EncPublicKey256(int index) throws AFCryptoException;

    /**
     * <p> 获取模长为512的SM2签名公钥信息 </p>
     * <p> 获取模长为512的SM2签名公钥信息，可使用SM2PublicKeyByM512中的toString()方法查看密钥信息 例如：
     *   System.out.println(instance.getSM2SignPublicKey512(1).toString());
     *  </p>
     * @param index ：待获取的加密机内部密钥索引
     * @return ： 返回密码机内部指定索引的签名公钥信息
     * @throws AFCryptoException
     */
    SM2PublicKeyByM512 getSM2SignPublicKey512(int index) throws AFCryptoException;

    /**
     * <p> 获取模长为512的SM2加密公钥信息 </p>
     * <p> 获取模长为512的SM2加密公钥信息，可使用SM2PublicKeyByM512中的toString()方法查看密钥信息 例如：
     *   System.out.println(instance.getSM2EncPublicKey512(1).toString());
     *  </p>
     * @return ： 返回密码机内部指定索引的加密公钥信息
     * @throws AFCryptoException
     */
    SM2PublicKeyByM512 getSM2EncPublicKey512(int index) throws AFCryptoException;

    /**
     * <p> 生成模长为256的SM2密钥对 </p>
     * <p> 生成模长为256的SM2密钥对，可使用SM2KeyPairByM256中的toString()方法查看密钥信息 例如：
     *   System.out.println(instance.generateSM2KeyPair256().toString());
     *  </p>
     * @return ： 返回SM2密钥对
     * @throws AFCryptoException
     */
    SM2KeyPairByM256 generateSM2KeyPair256() throws AFCryptoException;

    /**
     * <p> 生成模长为512的SM2密钥对 </p>
     * <p> 生成模长为512的SM2密钥对，可使用SM2KeyPairByM512中的toString()方法查看密钥信息 例如：
     *   System.out.println(instance.generateSM2KeyPair512().toString());
     *  </p>
     * @return ： 返回SM2密钥对
     * @throws AFCryptoException
     */
    SM2KeyPairByM512 generateSM2KeyPair512() throws AFCryptoException;

    /**
     * <p> 使用模长为256的SM2内部密钥加密 </p>
     * <p> 使用模长为256的SM2内部密钥加密 ，可使用SM2CipherByM256中的toString()方法查看密钥信息 </p>
     * @param index ： SM2密钥密码机内部索引
     * @param data ：待加密的原始数据
     * @return ： 加密后的SM2数据结构
     * @throws AFCryptoException
     */
    SM2CipherByM256 SM2Encrypt256(int index, byte[] data) throws AFCryptoException;

    /**
     * <p> 使用模长为512的SM2内部密钥加密 </p>
     * <p> 使用模长为512的SM2内部密钥加密 ，可使用SM2CipherByM512中的toString()方法查看密钥信息 </p>
     * @param index ： SM2密钥密码机内部索引
     * @param data ：待加密的原始数据
     * @return ： 加密后的SM2数据结构
     * @throws AFCryptoException
     */
    SM2CipherByM512 SM2Encrypt512(int index, byte[] data) throws AFCryptoException;

    /**
     * <p> 使用模长为256的SM2内部密钥解密 </p>
     * <p> 使用模长为256的SM2内部密钥解密 </p>
     * @param index ： SM2密钥密码机内部索引
     * @param encodeData ：待解密的原始数据
     * @return ： 解密后的数据
     * @throws AFCryptoException
     */
    byte[] SM2Decrypt256(int index, SM2CipherByM256 encodeData) throws AFCryptoException;

    /**
     * <p> 使用模长为512的SM2内部密钥解密 </p>
     * <p> 使用模长为512的SM2内部密钥解密 </p>
     * @param index ： SM2密钥密码机内部索引
     * @param encodeData ：待解密的原始数据
     * @return ： 解密后的数据
     * @throws AFCryptoException
     */
    byte[] SM2Decrypt512(int index, SM2CipherByM512 encodeData) throws AFCryptoException;

    /**
     * <p> 使用模长为256的SM2外部密钥加密 </p>
     * <p> 使用模长为256的SM2外部密钥加密 ，可使用SM2CipherByM256中的toString()方法查看密钥信息 </p>
     * @param data ： 待加密的原始数据
     * @param publicKey ：外部模长为256的公钥信息
     * @return ： 加密后的SM2数据结构
     * @throws AFCryptoException
     */
    SM2CipherByM256 SM2Encrypt256(byte[] data, SM2PublicKeyByM256 publicKey) throws AFCryptoException;

    /**
     * <p> 使用模长为512的SM2外部密钥加密 </p>
     * <p> 使用模长为512的SM2外部密钥加密 ，可使用SM2CipherByM512中的toString()方法查看密钥信息 </p>
     * @param data ： 待加密的原始数据
     * @param publicKey ：外部模长为512的公钥信息
     * @return ： 加密后的SM2数据结构
     * @throws AFCryptoException
     */
    SM2CipherByM512 SM2Encrypt512(byte[] data, SM2PublicKeyByM512 publicKey) throws AFCryptoException;

    /**
     * <p> 使用模长为256的SM2外部密钥解密 </p>
     * <p> 使用模长为256的SM2外部密钥解密 </p>
     * @param encodeData ： 待解密的SM2密文数据结构
     * @param privateKey ：外部模长为256的私钥信息
     * @return ： 解密后的数据
     * @throws AFCryptoException
     */
    byte[] SM2Decrypt256(SM2CipherByM256 encodeData, SM2PrivateKeyByM256 privateKey) throws AFCryptoException;

    /**
     * <p> 使用模长为512的SM2外部密钥解密 </p>
     * <p> 使用模长为512的SM2外部密钥解密 </p>
     * @param encodeData ： 待解密的SM2密文数据结构
     * @param privateKey ：外部模长为512的私钥信息
     * @return ： 解密后的数据
     * @throws AFCryptoException
     */
    byte[] SM2Decrypt512(SM2CipherByM512 encodeData, SM2PrivateKeyByM512 privateKey) throws AFCryptoException;

    /**
     * <p> 使用模长为256的SM2内部密钥签名 </p>
     * <p> 使用模长为256的SM2内部密钥签名， 可使用SM2SignatureByM256中的toString()方法查看信息</p>
     * @param index ：待签名的密码机内部密钥索引
     * @param data ：待签名的数据
     * @return ： 签名后的SM2数据结构
     * @throws AFCryptoException
     */
    SM2SignatureByM256 SM2Signature256(int index, byte[] data) throws AFCryptoException;

    /**
     * <p> 使用模长为512的SM2内部密钥签名 </p>
     * <p> 使用模长为512的SM2内部密钥签名， 可使用SM2SignatureByM512中的toString()方法查看信息</p>
     * @param index ：待签名的密码机内部密钥索引
     * @param data ：待签名的数据
     * @return ： 签名后的SM2数据结构
     * @throws AFCryptoException
     */
    SM2SignatureByM512 SM2Signature512(int index, byte[] data) throws AFCryptoException;

    /**
     * <p> 使用模长为256的SM2内部密钥验证签名 </p>
     * <p> 使用模长为256的SM2内部密钥签名</p>
     * @param index ：验证签名的密码机内部密钥索引
     * @param data ：待验证的原始数据
     * @param signature : 待验证的签名数据结构
     * @return ： 验证结果（true ：验证通过，false：验证失败）
     * @throws AFCryptoException
     */
    boolean SM2Verify256(int index, byte[] data, SM2SignatureByM256 signature) throws AFCryptoException;

    /**
     * <p> 使用模长为512的SM2内部密钥验证签名 </p>
     * <p> 使用模长为512的SM2内部密钥签名</p>
     * @param index ：验证签名的密码机内部密钥索引
     * @param data ：待验证的原始数据
     * @param signature : 待验证的签名数据结构
     * @return ： 验证结果（true ：验证通过，false：验证失败）
     * @throws AFCryptoException
     */
    boolean SM2Verify512(int index, byte[] data, SM2SignatureByM512 signature) throws AFCryptoException;

    /**
     * <p> 使用模长为256的SM2外部密钥签名 </p>
     * <p> 使用模长为256的SM2外部密钥签名， 可使用SM2SignatureByM256中的toString()方法查看信息</p>
     * @param data ：待签名的数据
     * @param privateKey ：签名使用的模长为256的外部SM2私钥结构
     * @return ： 签名后的SM2数据结构
     * @throws AFCryptoException
     */
    SM2SignatureByM256 SM2Signature256(byte[] data, SM2PrivateKeyByM256 privateKey) throws AFCryptoException;

    /**
     * <p> 使用模长为512的SM2内部密钥签名 </p>
     * <p> 使用模长为512的SM2内部密钥签名， 可使用SM2SignatureByM512中的toString()方法查看信息</p>
     * @param data ：待签名的数据
     * @param privateKey ：签名使用的模长为512的外部SM2私钥结构
     * @return ： 签名后的SM2数据结构
     * @throws AFCryptoException
     */
    SM2SignatureByM512 SM2Signature512(byte[] data, SM2PrivateKeyByM512 privateKey) throws AFCryptoException;

    /**
     * <p> 使用模长为256的SM2外部密钥验证签名 </p>
     * <p> 使用模长为256的SM2外部密钥签名</p>
     * @param data ：待验证的原始数据
     * @param signature ：待验证的签名数据结构
     * @param publicKey : 验证签名使用的模长为256的外部SM2私钥结构
     * @return ： 验证结果（true ：验证通过，false：验证失败）
     * @throws AFCryptoException
     */
    boolean SM2Verify256(byte[] data, SM2SignatureByM256 signature, SM2PublicKeyByM256 publicKey) throws AFCryptoException;

    /**
     * <p> 使用模长为512的SM2内部密钥验证签名 </p>
     * <p> 使用模长为512的SM2内部密钥签名</p>
     * @param data ：待验证的原始数据
     * @param signature ：待验证的签名数据结构
     * @param publicKey : 验证签名使用的模长为512的外部SM2私钥结构
     * @return ： 验证结果（true ：验证通过，false：验证失败）
     * @throws AFCryptoException
     */
    boolean SM2Verify512(byte[] data, SM2SignatureByM512 signature, SM2PublicKeyByM512 publicKey) throws AFCryptoException;

    /**
     *  <p> SM4 ECB模式内部密钥加密 </p>
     * @param index ： 加密机内部密钥索引
     * @param data ： 待加密的原始数据
     * @return ：加密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM4EncryptByECB(int index, byte[] data) throws AFCryptoException;

    /**
     *  <p> SM4 CBC模式内部密钥加密 </p>
     * @param index ： 加密机内部密钥索引
     * @param data ： 待加密的原始数据
     * @param IV ： 原始IV数据
     * @return ：加密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM4EncryptByCBC(int index, byte[] data, byte[] IV) throws AFCryptoException;

    /**
     *  <p> SM4 ECB模式内部密钥解密 </p>
     * @param index ： 加密机内部密钥索引
     * @param encodeData ： 待解密的原始数据
     * @return ：解密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM4DecryptByECB(int index, byte[] encodeData) throws AFCryptoException;

    /**
     *  <p> SM4 CBC模式内部密钥解密 </p>
     * @param index ： 加密机内部密钥索引
     * @param encodeData ： 待解密的原始数据
     * @param IV ： 原始IV数据
     * @return ：解密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM4DecryptByCBC(int index, byte[] encodeData, byte[] IV) throws AFCryptoException;

    /**
     *  <p> SM4 ECB模式外部密钥加密 </p>
     * @param key ： 外部对称密钥
     * @param data ： 待加密的原始数据
     * @return ：加密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM4EncryptByECB(byte[] key, byte[] data) throws AFCryptoException;

    /**
     *  <p> SM4 CBC模式外部密钥加密 </p>
     * @param key ： 外部对称密钥
     * @param data ： 待加密的原始数据
     * @param IV ： 原始IV数据
     * @return ：加密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM4EncryptByCBC(byte[] key, byte[] data, byte[] IV) throws AFCryptoException;

    /**
     *  <p> SM4 ECB模式外部密钥解密 </p>
     * @param key ： 外部对称密钥
     * @param encodeData ： 待解密的原始数据
     * @return ：解密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM4DecryptByECB(byte[] key, byte[] encodeData) throws AFCryptoException;

    /**
     *  <p> SM4 CBC模式外部密钥解密 </p>
     * @param key ： 外部对称密钥
     * @param encodeData ： 待解密的原始数据
     * @param IV ： 原始IV数据
     * @return ：解密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM4DecryptByCBC(byte[] key, byte[] encodeData, byte[] IV) throws AFCryptoException;

    /**
     *  <p> SM1 ECB模式内部密钥加密 </p>
     * @param index ： 加密机内部密钥索引
     * @param data ： 待加密的原始数据
     * @return ：加密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM1EncryptByECB(int index, byte[] data) throws AFCryptoException;

    /**
     *  <p> SM1 CBC模式内部密钥加密 </p>
     * @param index ： 加密机内部密钥索引
     * @param data ： 待加密的原始数据
     * @param IV ： 原始IV数据
     * @return ：加密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM1EncryptByCBC(int index, byte[] data, byte[] IV) throws AFCryptoException;

    /**
     *  <p> SM1 ECB模式内部密钥解密 </p>
     * @param index ： 加密机内部密钥索引
     * @param encodeData ： 待解密的原始数据
     * @return ：解密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM1DecryptByECB(int index, byte[] encodeData) throws AFCryptoException;

    /**
     *  <p> SM1 CBC模式内部密钥解密 </p>
     * @param index ： 加密机内部密钥索引
     * @param encodeData ： 待解密的原始数据
     * @param IV ： 原始IV数据
     * @return ：解密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM1DecryptByCBC(int index, byte[] encodeData, byte[] IV) throws AFCryptoException;

    /**
     *  <p> SM1 ECB模式外部密钥加密 </p>
     * @param key ： 外部对称密钥
     * @param data ： 待加密的原始数据
     * @return ：加密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM1EncryptByECB(byte[] key, byte[] data) throws AFCryptoException;

    /**
     *  <p> SM1 CBC模式外部密钥加密 </p>
     * @param key ： 外部对称密钥
     * @param data ： 待加密的原始数据
     * @param IV ： 原始IV数据
     * @return ：加密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM1EncryptByCBC(byte[] key, byte[] data, byte[] IV) throws AFCryptoException;

    /**
     *  <p> SM1 ECB模式外部密钥解密 </p>
     * @param key ： 外部对称密钥
     * @param encodeData ： 待解密的原始数据
     * @return ：解密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM1DecryptByECB(byte[] key, byte[] encodeData) throws AFCryptoException;

    /**
     *  <p> SM1 CBC模式外部密钥解密 </p>
     * @param key ： 外部对称密钥
     * @param encodeData ： 待解密的原始数据
     * @param IV ： 原始IV数据
     * @return ：解密后密文数据
     * @throws AFCryptoException
     */
    byte[] SM1DecryptByCBC(byte[] key, byte[] encodeData, byte[] IV) throws AFCryptoException;

    /**
     * <p> SM3 HASH杂凑算法 </p>
     * @param data ：待计算杂凑值的原始数据
     * @return ： 杂凑值
     * @throws AFCryptoException
     */
    byte[] SM3Hash(byte[] data) throws AFCryptoException;

    /**
     * <p> SM3 HASH杂凑算法 </p>
     * <p> SM3 HASH杂凑算法 带公钥信息（模长为256的SM2公钥信息）和用户ID </p>
     * @param data ：待计算杂凑值的原始数据
     * @param publicKey ：模长为256的SM2公钥信息
     * @param userID ：用户ID
     * @return ： 杂凑值
     * @throws AFCryptoException
     */
    byte[] SM3HashWithPublicKey256(byte[] data, SM2PublicKeyByM256 publicKey, byte[] userID) throws AFCryptoException;

    /**
     * <p> SM3 HASH杂凑算法 </p>
     * <p> SM3 HASH杂凑算法 带公钥信息（模长为512的SM2公钥信息）和用户ID </p>
     * @param data ：待计算杂凑值的原始数据
     * @param publicKey ：模长为512的SM2公钥信息
     * @param userID ：用户ID
     * @return ： 杂凑值
     * @throws AFCryptoException
     */
    byte[] SM3HashWithPublicKey512(byte[] data, SM2PublicKeyByM512 publicKey, byte[] userID) throws AFCryptoException;

    /**
     * <p> SM3 HMAC 算法</p>
     * @param index ： 指定的密码机内部密钥索引
     * @param data ：带计算的原始数据
     * @return ：返回HMAC计算结果
     * @throws AFCryptoException
     */
    byte[] SM3HMac(int index, byte[] data) throws AFCryptoException;

    /**
     * <p> SM3 HMAC 算法</p>
     * @param key ： 用户指定的外部密钥
     * @param data ：带计算的原始数据
     * @return ：返回HMAC计算结果
     * @throws AFCryptoException
     */
    byte[] SM3HMac(byte[] key, byte[] data) throws AFCryptoException;

    /**
     * <p> SM4 MAC 算法</p>
     * @param index ：  指定的密码机内部密钥索引
     * @param data ：带计算的原始数据
     * @param IV ：原始IV数据
     * @return ：返回MAC计算结果
     * @throws AFCryptoException
     */
    byte[] SM4Mac(int index, byte[] data, byte[] IV) throws AFCryptoException;

    /**
     * <p> SM4 MAC 算法</p>
     * @param key ：  用户指定的外部密钥
     * @param data ：带计算的原始数据
     * @param IV ：原始IV数据
     * @return ：返回MAC计算结果
     * @throws AFCryptoException
     */
    byte[] SM4Mac(byte[] key, byte[] data, byte[] IV) throws AFCryptoException;

    /**
     * <p> 获取RSA签名公钥信息 </p>
     *
     * @param index：密钥索引
     * @return 返回RSA签名数据结构
     * @throws AFCryptoException
     */
    RSAPublicKEY getRSASignPublicKey(int index) throws AFCryptoException;

    /**
     * <p> 获取RSA加密公钥信息 </p>
     *
     * @param index： 密钥索引
     * @return 返回RSA加密数据结构
     * @throws AFCryptoException
     */
    RSAPublicKEY getRSAEncPublicKey(int index) throws AFCryptoException;

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
    byte[] RSAExternalEncode(RSAPublicKEY publicKey, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA外部解密运算 </p>
     *
     * @param prvKey ：RSA私钥信息
     * @param data   : 加密数据
     * @return ：返回运算结果
     */
    byte[] RSAExternalDecode(RSAPrivateKEY prvKey, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA外部签名运算 </p>
     *
     * @param prvKey ：RSA私钥信息
     * @param data   : 原始数据
     * @return ：返回运算结果
     */
    byte[] RSAExternalSign(RSAPrivateKEY prvKey, byte[] data) throws AFCryptoException;

    /**
     * <p> RSA外部验证签名运算 </p>
     *
     * @param publicKey ：RSA公钥信息
     * @param data      : 签名数据
     * @param rawData   : 原始数据
     * @return ：true: 验证成功，false：验证失败
     */
    boolean RSAExternalVerify(RSAPublicKEY publicKey, byte[] data, byte[] rawData) throws AFCryptoException;

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

    /**
     * <p> 获取私钥访问授权 </p>
     *
     * @param keyIndex   ：内部密钥索引
     * @param keyType   ：密钥类型，1：RSA；0：SM2
     * @param passwd    : 私钥访问授权码
     * @return ：0: 成功，非0：失败
     */
    int getPrivateKeyAccessRight(int keyIndex, int keyType, byte[] passwd) throws AFCryptoException;

    /**
     * <p>获取密码设备内部对称密钥状态</p>
     *
     * @return ：返回密钥状态数据列表
     * @throws AFCryptoException
     */
    List<AFSymmetricKeyStatus> getSymmetricKeyStatus() throws AFCryptoException;

    /**
     * <p>导入非易失对称密钥 </p>
     *
     * @param index   ：对称密钥索引值
     * @param keyData : 对称密钥（16进制编码）
     * @throws AFCryptoException
     */
    void importKek(int index, byte[] keyData) throws AFCryptoException;

    /**
     * <p>销毁非易失对称密钥 </p>
     *
     * @param index ：对称密钥索引值
     * @throws AFCryptoException
     */
    void delKek(int index) throws AFCryptoException;

    /**
     * <p>生成密钥信息</p>
     *
     * @param keyType ：密钥类型 1:对称密钥，3:SM2密钥，4:RSA密钥
     * @param keyBits ：密钥长度/模长
     * @param count   : 生成的密钥个数
     * @return ：返回密钥信息列表
     * @throws AFCryptoException
     */
    List<AFKmsKeyInfo> generateKey(int keyType, int keyBits, int count) throws AFCryptoException;
}
