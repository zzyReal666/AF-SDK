package com.szaf.utils.pkcs;

public class AFPkcs1Operate {

    //签名填充
    public static byte[] pkcs1EncryptionPrivate(int modulus, byte[] inData) {
        int maxInDataLen = (modulus / 8) - 11;
        if (inData.length > maxInDataLen) {
            throw new RuntimeException("填充数据的最大值超过上限");
        }

        int inBlockSize = (modulus + 7) / 8 - 1;

        byte[] out = new byte[inBlockSize + 1];
        out[0] = 0x00;
        out[1] = 0x01;

        for (int i = 2; i != inBlockSize - inData.length; ++i) {
            out[i] = (byte) 0xFF;
        }

        out[inBlockSize - inData.length] = 0x00;
        byte[] outData = new byte[modulus / 8];

        System.arraycopy(inData, 0, out, inBlockSize - inData.length + 1, inData.length);
        System.arraycopy(out, 0, outData, 0, modulus / 8);
        return outData;
    }

    //验签去填充
    public static byte[] pkcs1DecryptionPrivate(int modulus, byte[] inData) {
        if (inData.length != (modulus / 8)) {
            throw new RuntimeException("输入数据长度错误");
        }

        byte typeFirst = inData[0];
        byte typeSecond = inData[1];

        if ((typeFirst != 0x00) || (typeSecond != 0x01)) {
            throw new RuntimeException("输入数据编码不合法");
        }

        int start = 0;

        for (start = 2; start != inData.length; ++start) {
            byte pad = inData[start];
            if (pad == 0x00) break;
            if (pad != (byte) 0xFF) {
                throw new RuntimeException("输入的数据填充编码不合法");
            }
        }

        ++start;

        if ((start > inData.length) || start < 10) {
            throw new RuntimeException("没有需要解析的数据");
        }

        byte[] out = new byte[inData.length - start];
        System.arraycopy(inData, start, out, 0, inData.length - start);

        return out;
    }

    //加密填充
    public static byte[] pkcs1EncryptionPublicKey(int modulus, byte[] inData) {
        int maxInDataLen = (modulus / 8) - 11;
        if (inData.length > maxInDataLen) {
            throw new RuntimeException("填充数据的最大值超过上限");
        }

        int inBlockSize = (modulus + 7) / 8 - 1;
        byte[] out = new byte[inBlockSize + 1];

        out[0] = 0x00;
        out[1] = 0x02;

        for (int i = 2; i != inBlockSize - inData.length; ++i) {
            out[i] = (byte) ((int) (Math.random() * (256)) & 0xFF);
            while (out[i] == (byte) 0x00) {
                out[i] = (byte) ((int) (Math.random() * (256)) & 0xFF);
            }
        }

        out[inBlockSize - inData.length] = 0x00;
        byte[] outData = new byte[modulus / 8];
        System.arraycopy(inData, 0, out, inBlockSize - inData.length + 1, inData.length);
        System.arraycopy(out, 0, outData, 0, modulus / 8);

        return outData;
    }

    //解密去填充
    public static byte[] pkcs1DecryptPublicKey(int modulus, byte[] inData) {
        if (inData.length != modulus / 8) {
            throw new RuntimeException("输入数据长度错误");
        }

        byte typeFirst = inData[0];
        byte typeSecond = inData[1];

        if ((typeFirst != 0x00) || (typeSecond != 0x02)) {
            throw new RuntimeException("输入数据编码不合法");
        }

        int start = 0;
        for (start = 2; start != inData.length; ++start) {
            byte pad = inData[start];
            if (pad == 0x00) break;
        }

        ++start;

        if ((start > inData.length) || start < 10) {
            throw new RuntimeException("没有需要解析的数据");
        }

        byte[] out = new byte[inData.length - start];

        System.arraycopy(inData, start, out, 0, inData.length - start);

        return out;
    }
}
