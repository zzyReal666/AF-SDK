package com.af.device.impl;

import com.af.constant.GroupMode;
import com.af.crypto.algorithm.sm1.SM1;
import com.af.crypto.algorithm.sm1.SM1Impl;
import com.af.crypto.algorithm.sm2.SM2;
import com.af.crypto.algorithm.sm2.SM2Impl;
import com.af.crypto.algorithm.sm3.SM3;
import com.af.crypto.algorithm.sm3.SM3Impl;
import com.af.crypto.algorithm.sm4.SM4;
import com.af.crypto.algorithm.sm4.SM4Impl;
import com.af.crypto.key.AFKmsKeyInfo;
import com.af.crypto.key.AFSymmetricKeyStatus;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PriKey;
import com.af.crypto.key.sm2.SM2PubKey;
import com.af.crypto.struct.impl.SM2Cipher;
import com.af.crypto.struct.impl.SM2Signature;
import com.af.device.DeviceInfo;
import com.af.device.IAFDevice;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;

import java.util.List;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description  HSM设备实现类 用于实现HSM设备的各种算法
 * @since 2023/4/27 14:53
 */
public class AFHsmDevice implements IAFDevice {

    private AFNettyClient nettyClient; //netty客户端
    private final SM1 sm1 = new SM1Impl();
    private final SM2 sm2 = new SM2Impl();
    private final SM3 sm3 = new SM3Impl();
    private final SM4 sm4 = new SM4Impl();


    private static final class InstanceHolder {
        static final AFHsmDevice instance = new AFHsmDevice();
    }
    public static AFHsmDevice getInstance() {
        return InstanceHolder.instance;
    }


    /**
     * 获取设备信息
     *
     * @return 设备信息
     * @throws AFCryptoException 获取设备信息异常
     */
    @Override
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        return null;
    }

    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * @throws AFCryptoException 获取随机数异常
     */
    @Override
    public byte[] getRandom(int length) throws AFCryptoException {
        return new byte[0];
    }

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
    @Override
    public byte[] SM1Encrypt(GroupMode mode, int index, byte[] iv, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

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
    @Override
    public byte[] SM1Decrypt(GroupMode mode, int index, byte[] iv, byte[] encodeData) throws AFCryptoException {
        return new byte[0];
    }

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
    @Override
    public byte[] SM1Encrypt(GroupMode mode, byte[] key, byte[] iv, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

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
    @Override
    public byte[] SM1Decrypt(GroupMode mode, byte[] key, byte[] iv, byte[] encodeData) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * 获取SM2签名公钥
     *
     * @param index 索引
     * @return SM2签名公钥 默认512位, 如果需要256位, 请调用{@link SM2PubKey#to256()}
     * @throws AFCryptoException 获取SM2签名公钥异常
     */
    @Override
    public SM2PubKey getSM2SignPublicKey(int index) throws AFCryptoException {
        return null;
    }

    /**
     * 获取SM2加密公钥
     *
     * @param index 索引
     * @return SM2加密公钥 默认512位, 如果需要256位, 请调用{@link SM2PubKey#to256()}
     * @throws AFCryptoException 获取SM2加密公钥异常
     */
    @Override
    public SM2PubKey getSM2EncryptPublicKey(int index) throws AFCryptoException {
        return null;
    }

    /**
     * 生成SM2密钥对
     *
     * @return SM2密钥对 默认512位, 如果需要256位, 请调用{@link SM2KeyPair#to256()}
     * @throws AFCryptoException 生成SM2密钥对异常
     */
    @Override
    public SM2KeyPair generateSM2KeyPair() throws AFCryptoException {
        return null;
    }

    /**
     * SM2内部密钥加密
     *
     * @param index 索引
     * @param data  待加密数据
     * @return 加密后的SM2Cipher对象 默认512位, 如果需要256位, 请调用{@link SM2Cipher#to256()}
     * @throws AFCryptoException 加密异常
     */
    @Override
    public SM2Cipher SM2Encrypt(int index, byte[] data) throws AFCryptoException {
        return null;
    }

    /**
     * SM2内部密钥解密
     *
     * @param index      索引
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM2Decrypt(int index, SM2Cipher encodeData) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM2外部密钥加密
     *
     * @param key  密钥
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */
    @Override
    public SM2Cipher SM2Encrypt(SM2PubKey key, byte[] data) throws AFCryptoException {
        return null;
    }

    /**
     * SM2外部密钥解密
     *
     * @param key        密钥
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */
    @Override
    public byte[] SM2Decrypt(SM2PubKey key, SM2Cipher encodeData) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM2 内部密钥签名
     *
     * @param index 密钥索引
     * @param data  待签名数据
     * @throws AFCryptoException 签名异常
     */
    @Override
    public SM2Signature SM2Signature(int index, byte[] data) throws AFCryptoException {
        return null;
    }

    /**
     * SM2 内部密钥验签
     *
     * @param index     密钥索引
     * @param data      待验签数据
     * @param signature 签名
     * @return 验签结果 true:验签成功 false:验签失败
     * @throws AFCryptoException 验签异常
     */
    @Override
    public boolean SM2Verify(int index, byte[] data, SM2Signature signature) throws AFCryptoException {
        return false;
    }

    /**
     * SM2 外部密钥签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return 签名
     * @throws AFCryptoException 签名异常
     */
    @Override
    public SM2Signature SM2Signature(byte[] data, SM2PriKey privateKey) throws AFCryptoException {
        return null;
    }

    /**
     * SM2 外部密钥验签
     *
     * @param data      待验签数据
     * @param signature 签名
     * @param publicKey 公钥
     * @return 验签结果 true:验签成功 false:验签失败
     * @throws AFCryptoException 验签异常
     */
    @Override
    public boolean SM2Verify(byte[] data, SM2Signature signature, SM2PubKey publicKey) throws AFCryptoException {
        return false;
    }

    /**
     * SM3哈希 杂凑算法
     *
     * @param data 待杂凑数据
     * @return 杂凑值
     * @throws AFCryptoException 杂凑异常
     */
    @Override
    public byte[] SM3Hash(byte[] data) throws AFCryptoException {
        return new byte[0];
    }

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
    @Override
    public byte[] SM3HashWithPubKey(byte[] data, SM2PubKey publicKey, byte[] userID) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM3 HMAC  内部密钥<br>
     *
     * @param index 内部密钥索引
     * @param data  待杂凑数据
     * @return 消息验证码值
     * @throws AFCryptoException 杂凑异常
     */
    @Override
    public byte[] SM3HMac(int index, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM3 HMAC  外部密钥<br>
     *
     * @param key  密钥
     * @param data 待杂凑数据
     * @return 消息验证码值
     * @throws AFCryptoException 杂凑异常
     */
    @Override
    public byte[] SM3HMac(byte[] key, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    @Override
    public byte[] SM4Mac(int index, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }

    @Override
    public byte[] SM4Mac(byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }

    @Override
    public byte[] SM4Encrypt(GroupMode mode, int index, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }

    @Override
    public byte[] SM4Decrypt(GroupMode mode, int index, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }

    @Override
    public byte[] SM4Encrypt(GroupMode mode, byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }

    @Override
    public byte[] SM4Decrypt(GroupMode mode, byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * 获取私钥访问权限
     *
     * @param keyIndex 密钥索引
     * @param keyType  密钥类型 1:RSA; 0:SM2;
     * @param passwd   私钥访问权限口令
     * @return 0:成功; 非0:失败
     * @throws AFCryptoException 获取私钥访问权限异常
     */
    @Override
    public int getPrivateKeyAccessRight(int keyIndex, int keyType, byte[] passwd) throws AFCryptoException {
        return 0;
    }

    /**
     * 获取设备内部对称密钥状态
     *
     * @return 设备内部对称密钥状态
     * @throws AFCryptoException 获取设备内部对称密钥状态异常
     */
    @Override
    public List<AFSymmetricKeyStatus> getSymmetricKeyStatus() throws AFCryptoException {
        return null;
    }

    /**
     * 导入非易失对称密钥
     *
     * @param index   密钥索引
     * @param keyData 密钥数据(16进制编码)
     * @throws AFCryptoException 导入非易失对称密钥异常
     */
    @Override
    public void importKek(int index, byte[] keyData) throws AFCryptoException {

    }

    /**
     * 销毁非易失对称密钥
     *
     * @param index 密钥索引
     * @throws AFCryptoException 销毁非易失对称密钥异常
     */
    @Override
    public void delKek(int index) throws AFCryptoException {

    }

    /**
     * 生成密钥信息
     *
     * @param keyType 密钥类型 1:对称密钥; 3:SM2密钥 4:RSA密钥;
     * @param keyBits 密钥长度 128/256/512/1024/2048/4096
     * @param count   密钥数量
     * @return 密钥信息列表
     * @throws AFCryptoException 生成密钥信息异常
     */
    @Override
    public List<AFKmsKeyInfo> generateKey(int keyType, int keyBits, int count) throws AFCryptoException {
        return null;
    }
}
