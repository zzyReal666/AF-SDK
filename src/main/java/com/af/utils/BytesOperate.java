package com.af.utils;


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


}
