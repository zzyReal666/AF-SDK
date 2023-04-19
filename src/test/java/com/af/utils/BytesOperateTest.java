package com.af.utils;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

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


    @Test
    void int2bytes() {
     int i = 7758521;
        byte[] bytes = BytesOperate.int2bytes(i);
        //遍历打印
        for (byte b : bytes) {
            System.out.println(b);
        }

        System.out.println("===============");
        byte[] array = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(i).array();
        for (byte b : array) {
            System.out.println(b);
        }


    }



}