package com.af.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;


class BytesOperateTest {

    @Test
    void bytes2int() {
        byte[] bytes = new byte[]{(byte) 0xff, 0x00, 0x00, 0x00};
        int i = BytesOperate.bytes2int(bytes, 0);
        assertEquals(255, i);
    }

    @Test
    void bytesToHexString() {
        byte[] bytes = new byte[]{(byte) 0xff, 0x00, 0x00, 0x00};
        String s = BytesOperate.bytesToHexString(bytes);
        assertEquals("ff000000", s);
    }



}