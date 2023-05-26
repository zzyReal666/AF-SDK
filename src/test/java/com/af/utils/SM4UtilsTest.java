package com.af.utils;

import org.junit.jupiter.api.Test;

class SM4UtilsTest {
    @Test
    void testEncrypt() {
        //测试sm4
        byte[] ROOT_KEY = {(byte) 0x46, (byte) 0xd3, (byte) 0xf4, (byte) 0x6d, (byte) 0x2e, (byte) 0xc2, (byte) 0x4a, (byte) 0xae, (byte) 0xb1, (byte) 0x84, (byte) 0x62,
                (byte) 0xdd, (byte) 0x86, (byte) 0x23, (byte) 0x71, (byte) 0xed};
        byte[] encrypt = SM4Utils.encrypt("1234567890abcdef".getBytes(), ROOT_KEY);
        System.out.println(encrypt.length);
    }

}