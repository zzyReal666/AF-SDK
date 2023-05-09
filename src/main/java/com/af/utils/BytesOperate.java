package com.af.utils;


import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Set;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 11:30
 */
public class BytesOperate {


    /**
     * byte[]转int  小端模式
     *
     * @param bytes 字节数组
     * @return int
     */
    public static int bytes2int(byte[] bytes) {
        return bytes2int(bytes, 0);
    }

    /**
     * byte[]转int  小端模式
     *
     * @param bytes  字节数组
     * @param offset 偏移量
     * @return int
     */
    public static int bytes2int(byte[] bytes, int offset) {
        int num = 0;
        int shift = 0;
        for (int i = 0; i < 4; ++i) {
            num |= (bytes[i + offset] & 0xFF) << shift;
            shift += 8;
        }
        return num;
    }
//    public static int bytes2int(byte[] bytes, int offset) {
//        int num = 0;
//
//        for (int i = 0; i < 4; ++i) {
//            num = (int) ((long) num + ((255L & (long) bytes[i + offset]) << i * 8));
//        }
//
//        return num;
//    }


    /**
     * 转换byte数组为16进制字符串   大端模式
     *
     * @param bytes 字节数组
     * @return 16进制字符串
     */
    public static String bytesToHexString(byte[] bytes) {
        //判空
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     * int 转换为byte数组  小端模式
     *
     * @param num
     * @return
     */
    public static byte[] int2bytes(int num) {
//        byte[] bytes = new byte[4];
//        for (int i = 0; i < 4; ++i) {
//            bytes[i] = (byte) (255 & num >> i * 8);
//        }
//        return bytes;
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(num).array();

    }

    /**
     * 封装数据 输入一个字节数组,返回一个封装好的字节数组
     */


    public byte[] packData(Set<byte[]> set) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] bytes : set) {
            out.write(bytes, 0, bytes.length);
        }
        return out.toByteArray();
    }

    /**
     * 从响应中截取指定的字节
     *
     * @param bytes  响应字节数组
     * @param offset 偏移量
     * @param length 长度
     * @return 截取后的字节数组
     */
    public static byte[] subBytes(byte[] bytes, int offset, int length) {
        byte[] buf = new byte[length];
        System.arraycopy(bytes, offset, buf, 0, length);
        return buf;
    }

}
