package com.szaf.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/18 14:09
 */
public enum TimeStampAlg {
    ;
    public static final int SGD_SM3 = 1;
    public static final int SGD_SHA1 = 2;
    public static final int SGD_SHA256 = 4;
    public static final int SGD_SHA384 = 8;
    public static final int SGD_SHA512 = 16;
    public static final int SGD_SHA224 = 32;
    public static final int SGD_MD5 = 64;
    public static final int SGD_SM3_RSA = 65537;
    public static final int SGD_SHA1_RSA = 65538;
    public static final int SGD_SHA256_RSA = 65540;
    public static final int SGD_SM3_SM2 = 131585;
    public static final int SGD_SM2 = 0x00020100;
}
