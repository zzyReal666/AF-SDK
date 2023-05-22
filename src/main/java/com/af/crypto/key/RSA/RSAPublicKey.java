package com.af.crypto.key.RSA;


import com.af.crypto.struct.IAFStruct;
import com.af.exception.AFCryptoException;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class RSAPublicKey implements IAFStruct {
    private int bits;
    private byte[] m = new byte[LiteRSARef_MAX_LEN];
    private byte[] e = new byte[LiteRSARef_MAX_LEN];

    //构造
    public RSAPublicKey(byte[] data) {
        try {
            this.decode(data);
        } catch (AFCryptoException e) {
            e.printStackTrace();
        }
    }

    @Override
    public int size() {
        return 4 + LiteRSARef_MAX_LEN * 2;
    }
    @Override
    public void decode(byte[] expPubKey) throws AFCryptoException {
        this.bits = BytesOperate.bytes2int(expPubKey, 0);
        System.arraycopy(expPubKey, 4, this.m, 0, LiteRSARef_MAX_LEN);
        System.arraycopy(expPubKey, 4 + LiteRSARef_MAX_LEN, this.e, 0, LiteRSARef_MAX_LEN);
    }
    @Override
    public byte[] encode() {
        return new BytesBuffer()
                .append(this.bits)
                .append(this.m)
                .append(this.e)
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
        return builder.toString();
    }
}
