package com.af.struct.impl.sm2;

import com.af.struct.IAFStruct;
import com.af.exception.AFCryptoException;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

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


    public SM2Cipher(byte[] data) throws AFCryptoException {
        this.length = 512;
        this.decode(data);
    }

    public SM2Cipher(int length, byte[] x, byte[] y, byte[] M, byte[] C) {
        this.length = x.length * 8;
        this.x = x;
        this.y = y;
        this.M = M;
        this.L = 136;
        this.C = C;
    }

    @Override
    public int size() {
        return 64 + 64 + 32 + 4 + 136;
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
        //todo 实际返回64字节(512位) 但是长度字段现在时0100(256位) 有待确认
        this.x = new byte[64];
        this.y = new byte[64];
        this.C = new byte[136];
        this.M = new byte[32];

        System.arraycopy(data, 0, this.x, 0, 64);
        System.arraycopy(data, 64, this.y, 0, 64);
        System.arraycopy(data, 128, this.M, 0, 32);
        this.L = BytesOperate.bytes2int(data, 64 + 64 + 32);
        System.arraycopy(data, 4+64+64+32, this.C, 0, 136);

    }

    @Override
    public byte[] encode() {
        return new BytesBuffer()
                .append(this.x)
                .append(this.y)
                .append(this.M)
                .append(this.L)
                .append(this.C)
                .toBytes();
    }

    public SM2Cipher to256() {
        if (this.length == 256) {
            return this;
        }
        SM2Cipher outCipher = new SM2Cipher();
        outCipher.setLength(256);
        byte[] outX = new byte[32];
        byte[] outY = new byte[32];
        byte[] outM = new byte[32];
        byte[] outC = new byte[136];

        outCipher.setL(this.getL());
        System.arraycopy(this.getX(), 32, outX, 0, 32);
        System.arraycopy(this.getY(), 32, outY, 0, 32);
        System.arraycopy(this.getM(), 0, outM, 0, 32);
        System.arraycopy(this.getC(), 0, outC, 0, 136);

        outCipher.setX(outX);
        outCipher.setY(outY);
        outCipher.setM(outM);
        outCipher.setC(outC);

        return outCipher;
    }

    public SM2Cipher to512() {
        if (this.length == 512) {
            return this;
        }
        SM2Cipher outCipher = new SM2Cipher();
        outCipher.setLength(512);
        byte[] outX = new byte[64];
        byte[] outY = new byte[64];
        byte[] outM = new byte[32];
        byte[] outC = new byte[136];

        outCipher.setL(this.getL());
        System.arraycopy(this.getX(), 0, outX, 32, 32);
        System.arraycopy(this.getY(), 0, outY, 32, 32);
        System.arraycopy(this.getM(), 0, outM, 0, 32);
        System.arraycopy(this.getC(), 0, outC, 0, 136);

        outCipher.setX(outX);
        outCipher.setY(outY);
        outCipher.setM(outM);
        outCipher.setC(outC);

        return outCipher;
    }



}
