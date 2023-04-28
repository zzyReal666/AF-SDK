package com.af.crypto.struct.impl;

import com.af.crypto.struct.IAFStruct;
import com.af.exception.AFCryptoException;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.nio.ByteBuffer;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description SM2密文结构
 * @since 2023/4/26 17:17
 */
@Getter
@Setter
@NoArgsConstructor
public class SM2Cipher implements IAFStruct {

    private int length; // 256位或者512位
    private byte[] x;   //x
    private byte[] y;   //y
    private byte[] M;   //明文SM3摘要值
    private int L;      //密文长度
    private byte[] C;   //密文


    public SM2Cipher(int length, byte[] x, byte[] y, byte[] M, byte[] C) {
        this.length = C.length * 8;
        this.x = x;
        this.y = y;
        this.M = M;
        this.L = C.length ;
        this.C = C;
    }
    @Override
    public int size() {
        return length / 8 + length / 8 + 32 + 4 + C.length;
    }


    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append("    |    project    |   value  ").append(nl);
        buf.append("   _|_______________|______________________________________________________").append(nl);
        buf.append("   1| length 512/256| ").append(this.length).append(nl);
        buf.append("   2| x             | ").append(BytesOperate.bytesToHexString(this.x)).append(nl);
        buf.append("   3| y             | ").append(BytesOperate.bytesToHexString(this.y)).append(nl);
        buf.append("   4| C             | ").append(BytesOperate.bytesToHexString(this.C)).append(nl);
        buf.append("   5| M             | ").append(BytesOperate.bytesToHexString(this.M)).append(nl);
        buf.append("   5| L             | ").append(L).append(nl);
        return buf.toString();
    }

    @Override
    public void decode(byte[] data) throws AFCryptoException {
        this.length = BytesOperate.bytes2int(data, 0);
        System.arraycopy(data, 4, this.x, 0, length / 8);
        System.arraycopy(data, 4 + length / 8, this.y, 0, length / 8);
        System.arraycopy(data, 4 + length / 8 + length / 8, this.C, 0, C.length);
        System.arraycopy(data, 4 + length / 8 + length / 8 + C.length, this.M, 0, length / 8);

    }

    @Override
    public byte[] encode() {
        return ByteBuffer.allocate(size())
                .put(x)
                .put(y)
                .put(M)
                .putInt(L)
                .put(C)
                .array();
    }


}
