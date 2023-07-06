package com.szaf.utils;

import java.math.BigInteger;

public class BigIntegerUtils {
    public static BigInteger toPositiveInteger(byte[] in) {
        if (in == null) {
            return null;
        } else {
            byte[] bt = null;
            if (in[0] < 0) {
                bt = new byte[in.length + 1];
                bt[0] = 0;
                System.arraycopy(in, 0, bt, 1, bt.length - 1);
            } else {
                bt = in;
            }

            return new BigInteger(bt);
        }
    }

    public static byte[] asUnsigned32ByteArray(BigInteger n) {
        return asUnsignedNByteArray(n, 32);
    }

    public static byte[] asUnsignedNByteArray(BigInteger x, int length) {
        if (x == null) {
            return null;
        } else {
            byte[] tmp = new byte[length];
            byte[] tmpXData = x.toByteArray();
            int len = tmpXData.length;
            if (len > length + 1) {
                return null;
            } else if (len == length + 1) {
                if (tmpXData[0] != 0) {
                    return null;
                } else {
                    System.arraycopy(tmpXData, 1, tmp, 0, length);
                    return tmp;
                }
            } else {
                if (len < length) {
                    System.arraycopy(tmpXData, 0, tmp, length - len, len);
                    if (x.signum() < 0) {
                        tmp[0] = -1;
                    }
                } else {
                    System.arraycopy(tmpXData, 0, tmp, length - len, len);
                }

                return tmp;
            }
        }
    }
}
