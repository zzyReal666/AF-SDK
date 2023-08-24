package com.af.struct.impl.RSA;

import com.af.struct.IAFStruct;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class RSAPriKey implements IAFStruct {

    private int bits;
    private byte[] m = new byte[LiteRSARef_MAX_LEN];
    private byte[] e = new byte[LiteRSARef_MAX_LEN];
    private byte[] d = new byte[LiteRSARef_MAX_LEN];
    private byte[] p = new byte[LiteRSARef_MAX_PLEN];
    private byte[] q = new byte[LiteRSARef_MAX_PLEN];
    private byte[] dp = new byte[LiteRSARef_MAX_PLEN];
    private byte[] dq = new byte[LiteRSARef_MAX_PLEN];
    private byte[] cof = new byte[LiteRSARef_MAX_PLEN];



    public RSAPriKey(byte[] data) {
        this.decode(data);
    }

    @Override
    public int size() {
        return 4 + 3 * LiteRSARef_MAX_LEN + 5 * LiteRSARef_MAX_PLEN;
    }

    @Override
    public void decode(byte[] expPrikey)  {
        this.bits = BytesOperate.bytes2int(expPrikey, 0);
        System.arraycopy(expPrikey, 4, this.m, 0, LiteRSARef_MAX_LEN);
        System.arraycopy(expPrikey, 4 + LiteRSARef_MAX_LEN, this.e, 0, LiteRSARef_MAX_LEN);
        System.arraycopy(expPrikey, 4 + LiteRSARef_MAX_LEN * 2, this.d, 0, LiteRSARef_MAX_LEN);
        System.arraycopy(expPrikey, 4 + LiteRSARef_MAX_LEN * 3, this.p, 0, LiteRSARef_MAX_PLEN);
        System.arraycopy(expPrikey, 4 + LiteRSARef_MAX_LEN * 3 + LiteRSARef_MAX_PLEN, this.q, 0, LiteRSARef_MAX_PLEN);
        System.arraycopy(expPrikey, 4 + LiteRSARef_MAX_LEN * 3 + LiteRSARef_MAX_PLEN * 2, this.dp, 0, LiteRSARef_MAX_PLEN);
        System.arraycopy(expPrikey, 4 + LiteRSARef_MAX_LEN * 3 + LiteRSARef_MAX_PLEN * 3, this.dq, 0, LiteRSARef_MAX_PLEN);
        System.arraycopy(expPrikey, 4 + LiteRSARef_MAX_LEN * 3 + LiteRSARef_MAX_PLEN * 4, this.cof, 0, LiteRSARef_MAX_PLEN);
    }

    @Override
    public byte[] encode() {
        return new BytesBuffer()
                .append(this.bits)
                .append(this.m)
                .append(this.e)
                .append(this.d)
                .append(this.p)
                .append(this.q)
                .append(this.dp)
                .append(this.dq)
                .append(this.cof)
                .toBytes();
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        String nl = System.getProperty("line.separator");
        builder.append("    |    project    |   value  ").append(nl);
        builder.append("   _|_______________|______________________________________________________").append(nl);
        builder.append("   1| bits          | ").append(Integer.toString(this.bits)).append(nl);
        builder.append("   2| m             | ").append(BytesOperate.bytesToHexString(this.m)).append(nl);
        builder.append("   3| e             | ").append(BytesOperate.bytesToHexString(this.e)).append(nl);
        builder.append("   4| d             | ").append(BytesOperate.bytesToHexString(this.d)).append(nl);
        builder.append("   5| q             | ").append(BytesOperate.bytesToHexString(this.p)).append(nl);
        builder.append("   6| q             | ").append(BytesOperate.bytesToHexString(this.q)).append(nl);
        builder.append("   7| dp            | ").append(BytesOperate.bytesToHexString(this.dp)).append(nl);
        builder.append("   8| dq            | ").append(BytesOperate.bytesToHexString(this.dq)).append(nl);
        builder.append("   9| cof           | ").append(BytesOperate.bytesToHexString(this.cof)).append(nl);
        return builder.toString();
    }
}