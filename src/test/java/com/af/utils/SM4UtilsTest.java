package com.af.utils;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.SM3;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class SM4UtilsTest {
    @Test
    void testEncrypt() {
        //测试sm4
        byte[] ROOT_KEY = {(byte) 0x46, (byte) 0xd3, (byte) 0xf4, (byte) 0x6d, (byte) 0x2e, (byte) 0xc2, (byte) 0x4a, (byte) 0xae, (byte) 0xb1, (byte) 0x84, (byte) 0x62,
                (byte) 0xdd, (byte) 0x86, (byte) 0x23, (byte) 0x71, (byte) 0xed};
//
//        byte[] data = "5".getBytes();
//
//        //加密
//        byte[] encrypt = SM4Utils.encrypt(data, SM4Utils.ROOT_KEY);
//        System.out.println("加密后的数据：" + HexUtil.encodeHexStr(encrypt));
//        //解密
//        byte[] decrypt = SM4Utils.decrypt(encrypt, ROOT_KEY);
//
//        System.out.println("解密后的数据：" + new String(decrypt));
//        assert Arrays.equals(data, decrypt);


//        String s = " 9185d58cfe9a5ca4257027e7862319d4";
//        //解密
//        byte[] decrypt1 = SM4Utils.decrypt(HexUtil.decodeHex(s), ROOT_KEY);
//        System.out.println("解密后的数据：" + Arrays.toString(decrypt1));
//

        byte[] key = HexUtil.decodeHex("d021a872fecbf54b9d11b661220b2d05");
        byte[] decrypt1 = SM4Utils.decrypt(HexUtil.decodeHex("6512c8c290e8fc80c555d72f57703512"), key);
        System.out.println("解密后的数据：" + Arrays.toString(decrypt1));


    }


    @Test
    void testEncrypt2() {
        byte[] param = "6512c8c290e8fc80c56512c8c290e8fc80c56512c8c290e8fc80c56512c8c290e8fc80c56512c8c290e8fc80c5".getBytes();
        byte[] digest = new SM3().digest(param);
        System.out.println("加密后的数据：" +digest.length);
    }

}