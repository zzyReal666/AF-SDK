package com.szaf.crypto.key;

import com.szaf.struct.IAFStruct;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/26 16:36
 */
public interface Key extends IAFStruct {

    String getAlgorithm();

    byte[] encode();

    void decode(byte[] encodedKey);
}
