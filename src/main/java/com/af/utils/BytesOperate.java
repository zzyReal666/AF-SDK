package com.af.utils;


import com.af.utils.base64.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
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

    public static byte[] base64DecodePubKey(String base64PubKey) {
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";
        String outPubKey = "";
        outPubKey = base64PubKey.replaceAll(begin, "");
        outPubKey = outPubKey.replaceAll(end, "");
        return base64DecodeData(outPubKey);
    }

    public static byte[] base64EncodeCert(byte[] derCert) {
        String begin = "-----BEGIN CERTIFICATE-----\n";
        String end = "\n-----END CERTIFICATE-----";
        return (begin + new String(base64EncodeData(derCert)) + end).getBytes(StandardCharsets.UTF_8);
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


    /**
     * 十六进制字符串转换为byte
     *
     * @param str 十六进制字符串
     * @return byte
     */
    public static byte[] hex2bytes(String str) {
        return hex2bytes(str, "");
    }

    /**
     * 十六进制字符串转换为byte
     *
     * @param str       十六进制字符串
     * @param delimiter 分隔符
     * @return byte
     */
    private static byte[] hex2bytes(String str, String delimiter) {
        str = str.toLowerCase();
        int i;
        if (!"".equals(delimiter)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            String[] arr = str.split(delimiter);

            for (i = 0; i < arr.length; ++i) {
                if (!arr[i].trim().equals("")) {
                    baos.write(hex2byte(arr[i]));
                }
            }

            return baos.toByteArray();
        } else {
            byte[] buf = new byte[str.length() / 2];

            for (i = 0; i < buf.length; ++i) {
                char ch = str.charAt(i * 2);
                if (ch >= 'a' && ch <= 'f') {
                    buf[i] = (byte) (ch - 97 + 10 << 4);
                } else {
                    buf[i] = (byte) (ch - 48 << 4);
                }

                ch = str.charAt(i * 2 + 1);
                if (ch >= 'a' && ch <= 'f') {
                    buf[i] += (byte) (ch - 97 + 10);
                } else {
                    buf[i] += (byte) (ch - 48);
                }
            }

            return buf;
        }
    }

    /**
     * 十六进制字符串转换为byte
     *
     * @param str 十六进制字符串
     * @return byte
     */
    private static byte hex2byte(String str) {
        char ch = str.charAt(0);
        byte n;
        if (ch >= 'a' && ch <= 'f') {
            n = (byte) (ch - 97 + 10 << 4);
        } else {
            n = (byte) (ch - 48 << 4);
        }
        ch = str.charAt(1);
        if (ch >= 'a' && ch <= 'f') {
            n += (byte) (ch - 97 + 10);
        } else {
            n += (byte) (ch - 48);
        }
        return n;
    }

    /**
     * base64编码
     *
     * @param data 待编码数据
     * @return String
     */
    public static byte[] base64EncodeData(byte[] data) {
        return Base64.encode(data);
    }


    /**
     * base64编码证书
     *
     * @param base64Cert base64编码证书文件
     * @return byte[]
     */
    public static byte[] base64DecodeCert(String base64Cert) {
        String begin = "-----BEGIN CERTIFICATE-----";
        String end = "-----END CERTIFICATE-----";
        String outCert;
        outCert = base64Cert.replaceAll(begin, "");
        outCert = outCert.replaceAll(end, "");
        return base64DecodeData(outCert);
    }

    /**
     * base64解码数据
     *
     * @param data base64解码数据
     * @return byte[]
     */
    public static byte[] base64DecodeData(String data) {
        return Base64.decode(data);
    }

    /**
     * base64解码数据
     */
    public static byte[] base64DecodeData(byte[] data) {
        return Base64.decode(data);
    }


    /**
     * base64编码CRL
     *
     * @param base64CRL base64编码CRL文件
     * @return byte[]
     */
    public static byte[] base64DecodeCRL(String base64CRL) {
        String begin = "-----BEGIN X509 CRL-----";
        String end = "-----END X509 CRL-----";
        String outCRL = "";
        outCRL = base64CRL.replaceAll(begin, "");
        outCRL = outCRL.replaceAll(end, "");
        return base64DecodeData(outCRL);
    }


    /**
     * base64 解码公钥
     *
     * @param base64PrivateKey base64编码公钥文件
     * @return byte[]
     */
    public static byte[] base64DecodePrivateKey(String base64PrivateKey) {
        String begin = "-----BEGIN EC PRIVATE KEY-----\n";
        String end = "\n-----END EC PRIVATE KEY-----";
        String outPubKey = "";
        outPubKey = base64PrivateKey.replaceAll(begin, "");
        outPubKey = outPubKey.replaceAll(end, "");
        return base64DecodeData(outPubKey);
    }


    /**
     * 读取文件
     *
     * @param filePath 文件路径
     */
    public static String readFileByLine(String filePath) {
        StringBuilder strLine = new StringBuilder();
        try {
            File file = new File(filePath);
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String tempStrLine = "";
            while (null != (tempStrLine = reader.readLine())) {
                strLine.append(tempStrLine);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strLine.toString();
    }

}
