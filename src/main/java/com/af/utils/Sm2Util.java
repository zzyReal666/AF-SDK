package com.af.utils;

import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.ByteUtil;
import cn.hutool.crypto.CryptoException;
import cn.hutool.crypto.ECKeyUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.SM2;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;

/**
 * 与硬件设备交互的数据均为GM/T0018格式
 * 
 * @author linzhj
 * @date 2022年4月22日
 */
public class Sm2Util {

    /** 32字节的0 */
    private static final byte[] ZERO_BYTES_32 = new byte[32];

    /**
     * 使用公钥加密
     * 
     * @param publicKey GM/T0018格式公钥（512bit）
     * @param data      明文
     * @return GM/T0018格式密文（x|y|M|L|C）
     */
    public static byte[] encrypt(byte[] publicKey, byte[] data) {
        byte[] raEncrypt = new SM2(null, Sm2Util.changePublicKey512ToQ(publicKey)).encrypt(data);
        return changeC1C3C2To512(raEncrypt);
    }

    /**
     * 使用私钥解密
     * 
     * @param privateKey 私钥D值
     * @param ciphertext GM/T0018格式密文（x|y|M|L|C）
     * @return
     */
    public static byte[] decrypt(byte[] privateKey, byte[] ciphertext) {
        ciphertext = Sm2Util.changeCipherToC1C3C2(ciphertext);
        return new SM2(ECKeyUtil.decodePrivateKeyParams(privateKey), null).decrypt(ciphertext);
    }

    /**
     * 用私钥对信息生成数字签名
     * 
     * @param privateKey 私钥D值
     * @param data       明文
     * @return 签名值 （512bits r|s）
     */
    public static byte[] sign(byte[] privateKey, byte[] data) {
        final SM2Signer signer = new SM2Signer();
        try {
            CipherParameters param = new ParametersWithRandom(ECKeyUtil.decodePrivateKeyParams(privateKey));
            signer.init(true, param);
            signer.update(data, 0, data.length);
            byte[] sign = signer.generateSignature();
            sign = SmUtil.rsAsn1ToPlain(sign);
            return changeSign256To512(sign);
        } catch (org.bouncycastle.crypto.CryptoException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 用公钥检验数字签名的合法性
     *
     * @param publicKey GM/T0018格式公钥（512bit）
     * @param data      原文
     * @param sign      GM/T0018格式签名值 （512bits r|s）
     * @return 是否验证通过
     */
    public static boolean verify(byte[] publicKey, byte[] data, byte[] sign) {
        sign = Sm2Util.changeSign512To256(sign);
        sign = SmUtil.rsPlainToAsn1(sign);
        final SM2Signer signer = new SM2Signer();
        signer.init(false, ECKeyUtil.decodePublicKeyParams(Sm2Util.changePublicKey512ToQ(publicKey)));
        signer.update(data, 0, data.length);
        return signer.verifySignature(sign);
    }

    /**
     * GM/T0018格式公钥转换成Q值
     * 
     * @param key GM/T0018格式公钥（512bit）
     * @return Q值 （33字节的04|x|y格式）
     */
    public static byte[] changePublicKey512ToQ(byte[] key) {
        BytesBuffer buf = new BytesBuffer();
        buf.append((byte) 0x04);
        buf.append(key, 4 + 32, 32); // x
        buf.append(key, 4 + 64 + 32, 32); // y
        return buf.toBytes();
    }

    /**
     * Q值转换成GM/T0018格式公钥
     * 
     * @param key Q值 （33字节的04|x|y格式）
     * @return GM/T0018格式公钥（512bit）
     */
    public static byte[] changePublicKeyQTo512(byte[] key) {
        BytesBuffer buf = new BytesBuffer();
        buf.append(256); // bits
        buf.append(ZERO_BYTES_32);
        buf.append(key, 1, 32); // x
        buf.append(ZERO_BYTES_32);
        buf.append(key, 1 + 32, 32); // y
        return buf.toBytes();
    }

    /**
     * C1C3C2格式密文转换成GM/T0018格式密文
     * 
     * @param ciphertext C1C3C2格式密文
     * @return GM/T0018格式密文（x|y|M|L|C）
     */
    public static byte[] changeC1C3C2To512(byte[] ciphertext) {
        BytesBuffer out = new BytesBuffer();
        int i = 1;
        out.append(ZERO_BYTES_32);
        out.append(ciphertext, i, 32); // x
        out.append(ZERO_BYTES_32);
        out.append(ciphertext, i = i + 32, 32); // y
        out.append(ciphertext, i = i + 32, 32); // M (C3)
        byte[] c = new byte[136];
        System.arraycopy(ciphertext, i + 32, c, 0, ciphertext.length - (i + 32));// C (C2)
        out.append(ciphertext.length - (i + 32)); // L
        out.append(c);
        return out.toBytes();
    }

    /**
     * GM/T0018格式密文转换成C1C3C2格式密文
     * 
     * @param ciphertext GM/T0018格式密文（x|y|M|L|C）
     * @return C1C3C2格式密文
     */
    public static byte[] changeCipherToC1C3C2(byte[] ciphertext) {
        BytesBuffer out = new BytesBuffer();
        out.append((byte) 0x04);
        int i = 0;
        out.append(ciphertext, i = i + 32, 32); // x
        out.append(ciphertext, i = i + 32 + 32, 32); // y
        out.append(ciphertext, i = i + 32, 32); // m
        int l = ByteUtil.bytesToInt(ArrayUtil.sub(ciphertext, i = i + 32, i + 4));
        out.append(ciphertext, i = i + 4, l); // c
        return out.toBytes();
    }

    /**
     * 256位签名值转换成GM/T0018格式
     * 
     * @param sign 256bits签名值 r|s
     * @return 512bits签名值 r|s
     */
    public static byte[] changeSign256To512(byte[] sign) {
        BytesBuffer out = new BytesBuffer();
        int i = 0;
        out.append(ZERO_BYTES_32);
        out.append(sign, i, 32); // r
        out.append(ZERO_BYTES_32);
        out.append(sign, i + 32, 32); // s
        return out.toBytes();
    }

    /**
     * GM/T0018格式签名值转换成256位签名值
     * 
     * @param sign 512bits签名值 r|s
     * @return 256bits签名值 r|s
     */
    public static byte[] changeSign512To256(byte[] sign) {
        BytesBuffer out = new BytesBuffer();
        int i = 0;
        out.append(sign, i + 32, 32); // r
        out.append(sign, i + 32 + 32 + 32, 32); // s
        return out.toBytes();
    }

}
