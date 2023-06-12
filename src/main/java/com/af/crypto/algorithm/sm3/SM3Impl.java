package com.af.crypto.algorithm.sm3;

import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.exception.AFCryptoException;
import com.af.struct.impl.sm3.SM3Digest;

import java.nio.ByteOrder;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/5 15:02
 */
public class SM3Impl implements SM3 {





    /**
     * SM3 hash
     *
     * @param data
     * @return
     * @throws AFCryptoException
     */
    @Override
    public byte[] SM3Hash(byte[] data) throws AFCryptoException {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] hashData = new byte[digest.getDigestSize()];
        digest.doFinal(hashData, 0);
        return hashData;
    }

    /**
     * SM3 hash with userID
     *
     * @param data      待hash数据
     * @param publicKey 公钥 256/512
     * @param userID    用户ID
     * @return hash结果
     * @throws AFCryptoException hash异常
     */
    @Override
    public byte[] SM3HashWithPublicKey256(byte[] data, SM2PublicKey publicKey, byte[] userID) throws AFCryptoException {
        SM3Digest digest = new SM3Digest();
        byte[] sm3SignHash = SM3SignerHash(publicKey.encode(), userID);
        byte[] newData = new byte[sm3SignHash.length + data.length];

        System.arraycopy(sm3SignHash, 0, newData, 0, sm3SignHash.length);
        System.arraycopy(data, 0, newData, sm3SignHash.length, data.length);

        digest.update(newData, 0, newData.length);
        byte[] hashData = new byte[digest.getDigestSize()];
        digest.doFinal(hashData, 0);
        return hashData;
    }

    private byte[] SM3SignerHash(byte[] pubkey, byte[] userID) throws AFCryptoException {
        byte[] a = {
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
        };

        byte[] b = {
                (byte) 0x28, (byte) 0xE9, (byte) 0xFA, (byte) 0x9E, (byte) 0x9D, (byte) 0x9F, (byte) 0x5E, (byte) 0x34,
                (byte) 0x4D, (byte) 0x5A, (byte) 0x9E, (byte) 0x4B, (byte) 0xCF, (byte) 0x65, (byte) 0x09, (byte) 0xA7,
                (byte) 0xF3, (byte) 0x97, (byte) 0x89, (byte) 0xF5, (byte) 0x15, (byte) 0xAB, (byte) 0x8F, (byte) 0x92,
                (byte) 0xDD, (byte) 0xBC, (byte) 0xBD, (byte) 0x41, (byte) 0x4D, (byte) 0x94, (byte) 0xE, (byte) 0x93
        };

        byte[] x_G = {
                (byte) 0x32, (byte) 0xC4, (byte) 0xAE, (byte) 0x2C, (byte) 0x1F, (byte) 0x19, (byte) 0x81, (byte) 0x19,
                (byte) 0x5F, (byte) 0x99, (byte) 0x4, (byte) 0x46, (byte) 0x6A, (byte) 0x39, (byte) 0xC9, (byte) 0x94,
                (byte) 0x8F, (byte) 0xE3, (byte) 0xB, (byte) 0xBF, (byte) 0xF2, (byte) 0x66, (byte) 0xB, (byte) 0xE1,
                (byte) 0x71, (byte) 0x5A, (byte) 0x45, (byte) 0x89, (byte) 0x33, (byte) 0x4C, (byte) 0x74, (byte) 0xC7
        };

        byte[] y_G = {
                (byte) 0xBC, (byte) 0x37, (byte) 0x36, (byte) 0xA2, (byte) 0xF4, (byte) 0xF6, (byte) 0x77, (byte) 0x9C,
                (byte) 0x59, (byte) 0xBD, (byte) 0xCE, (byte) 0xE3, (byte) 0x6B, (byte) 0x69, (byte) 0x21, (byte) 0x53,
                (byte) 0xD0, (byte) 0xA9, (byte) 0x87, (byte) 0x7C, (byte) 0xC6, (byte) 0x2A, (byte) 0x47, (byte) 0x40,
                (byte) 0x2, (byte) 0xDF, (byte) 0x32, (byte) 0xE5, (byte) 0x21, (byte) 0x39, (byte) 0xF0, (byte) 0xA0
        };

        short userIDBitsLen = (short) (userID.length * 8);
        byte[] pucData = new byte[2 + userID.length + 32 * 6];

        if (ByteOrder.nativeOrder() != ByteOrder.BIG_ENDIAN) {
            pucData[0] = (byte) ((userIDBitsLen >> 8) & 0xff);
            pucData[1] = (byte) (userIDBitsLen & 0xff);
        } else {
            pucData[0] = (byte) (userIDBitsLen & 0xff);
            pucData[1] = (byte) ((userIDBitsLen >> 8) & 0xff);
        }

        System.arraycopy(userID, 0, pucData, 2, userID.length);
        System.arraycopy(a, 0, pucData, 2 + userID.length, 32);
        System.arraycopy(b, 0, pucData, 2 + userID.length + 32, 32);
        System.arraycopy(x_G, 0, pucData, 2 + userID.length + 32 + 32, 32);
        System.arraycopy(y_G, 0, pucData, 2 + userID.length + 32 + 32 + 32, 32);
        System.arraycopy(pubkey, 4, pucData, 2 + userID.length + 32 + 32 + 32 + 32, 32);
        System.arraycopy(pubkey, 4 + 32, pucData, 2 + userID.length + 32 + 32 + 32 + 32 + 32, 32);

        return SM3Hash(pucData);
    }


}
