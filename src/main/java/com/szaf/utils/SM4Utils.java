package com.szaf.utils;

import cn.hutool.crypto.symmetric.SymmetricCrypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/18 10:35
 */
public class SM4Utils {
    //日志
  private static final Logger logger = LoggerFactory.getLogger(SM4Utils.class);

    public static final byte[] ROOT_KEY = {(byte) 0x46, (byte) 0xd3, (byte) 0xf4, (byte) 0x6d, (byte) 0x2e, (byte) 0xc2, (byte) 0x4a, (byte) 0xae, (byte) 0xb1, (byte) 0x84, (byte) 0x62,
            (byte) 0xdd, (byte) 0x86, (byte) 0x23, (byte) 0x71, (byte) 0xed};

    /**
     * 加密
     *
     * @param data 明文
     * @param key  密钥
     */
    public static byte[] encrypt(byte[] data, byte[] key) {
        SymmetricCrypto sm4 = new SymmetricCrypto("SM4/ECB/PKCS7Padding", key);
        return sm4.encrypt(data);

    }

    /**
     * 解密
     *
     * @param data 密文
     * @param key  密钥
     */
    public static byte[] decrypt(byte[] data, byte[] key) {
        SymmetricCrypto sm4 = new SymmetricCrypto("SM4/ECB/PKCS7Padding", key);
        return sm4.decrypt(data);
    }
}
