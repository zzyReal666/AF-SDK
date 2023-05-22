package com.af.crypto.key;

import com.af.crypto.struct.IAFStruct;

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
