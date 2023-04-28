package com.af.crypto.key;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/26 16:36
 */
public interface Key {

    String getAlgorithm();


    byte[] encode();

    void decode(byte[] encodedKey);
}
