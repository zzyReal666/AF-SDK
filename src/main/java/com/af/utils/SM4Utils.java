package com.af.utils;

import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.symmetric.SM4;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/18 10:35
 */
public class SM4Utils {

    public static byte[] encrypt(byte[] key, byte[] data) {
        SM4 sm4Padding = new SM4(Mode.ECB, Padding.PKCS5Padding, key);
        return sm4Padding.encrypt(data);
    }
}
