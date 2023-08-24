package com.af.crypto.key.keyInfo;

import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/6 10:01
 */
public interface KeyInfo {


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
//    List<AFSymmetricKeyStatus> getSymmetricKeyStatus(byte[] agreementKey) throws AFCryptoException;
//
//    /**
//     * 导入非易失对称密钥
//     *
//     * @param index   密钥索引
//     * @param keyData 密钥数据(16进制编码)
//     * @param agKey   协商密钥
//     * @throws AFCryptoException 导入非易失对称密钥异常
//     */
//    void importKek(int index, byte[] keyData,byte[] agKey) throws AFCryptoException;
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

    byte[] exportSymmKey(int index) throws AFCryptoException;

}
