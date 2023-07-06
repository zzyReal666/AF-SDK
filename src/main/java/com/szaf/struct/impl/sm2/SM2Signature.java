package com.szaf.struct.impl.sm2;

import com.szaf.struct.IAFStruct;
import com.szaf.utils.BytesBuffer;
import com.szaf.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description  SM2签名结构体 由r和s组成 r和s长度相同 且长度为32或者64 256位或者512位
 * @since 2023/5/4 10:50
 */
@Setter
@Getter
@NoArgsConstructor
public class SM2Signature implements IAFStruct {

    private int length; // 模长 256或者512
    private byte[] r;
    private byte[] s;

    public SM2Signature(byte[] data) {
        this.length = 512;
        decode(data);
    }
    public SM2Signature(byte[] r, byte[] s) {
        if (r.length != s.length) {
            throw new IllegalArgumentException("r and s length must be equal");
        }
        if (r.length != 32 && r.length != 64) {
            throw new IllegalArgumentException("r and s length must be 32 or 64");
        }
        this.length = r.length * 8;
        this.r = r;
        this.s = s;
    }

    @Override
    public int size() {
        return this.length * 2;
    }

    @Override
    public void decode(byte[] data)  {
        this.r = new byte[64];
        this.s = new byte[64];
        System.arraycopy(data, 0, this.r, 0, ECCref_MAX_LEN);
        System.arraycopy(data, ECCref_MAX_LEN, this.s, 0, ECCref_MAX_LEN);

    }

    @Override
    public byte[] encode() {
        BytesBuffer buf = new BytesBuffer();
        buf.append(this.r);
        buf.append(this.s);
        return buf.toBytes();
    }

    public SM2Signature to256() {
        if (this.length == 256) {
            return this;
        }
        this.length = 256;
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(this.r, 32, r, 0, 32);
        System.arraycopy(this.s, 32, s, 0, 32);
        return new SM2Signature(r, s);
    }

    public SM2Signature to512() {
        if (this.length == 512) {
            return this;
        }
        this.length = 512;
        byte[] r = new byte[64];
        byte[] s = new byte[64];
        System.arraycopy(this.r, 0, r, 32, 32);
        System.arraycopy(this.s, 0, s, 32, 32);
        return new SM2Signature(r, s);
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        String nl = System.getProperty("line.separator");
        builder.append("    |    project    |   value  ").append(nl);
        builder.append("   _|_______________|______________________________________________________").append(nl);
        builder.append("   1| r             | ").append(BytesOperate.bytesToHexString(this.r)).append(nl);
        builder.append("   2| s             | ").append(BytesOperate.bytesToHexString(this.s)).append(nl);
        builder.append("   2| length        | ").append(this.length).append(nl);
        return builder.toString();
    }

}
