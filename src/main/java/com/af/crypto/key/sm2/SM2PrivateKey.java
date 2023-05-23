package com.af.crypto.key.sm2;


import com.af.crypto.key.Key;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description     SM2私钥
 * @since 2023/4/26 16:52
 */
@Getter
@NoArgsConstructor
public class SM2PrivateKey implements Key {

    private int length; //密钥长度 256/512
    private byte[] D;   //私钥D

    public SM2PrivateKey(byte[] data) {
        this.decode(data);
    }

    public SM2PrivateKey(int length, byte[] d) {
        //如果length不是256或者512位 抛出异常
        if (length != 256 && length != 512) {
            throw new IllegalArgumentException("SM2PriKey长度(length)必须是256或者512,当前长度为:" + length + "位");
        }
        //如果d长度不等于length/8
        if (d.length != length / 8) {
            throw new IllegalArgumentException("SM2PriKey-D数组长度必须位32或者64字节,当前长度为:" + d.length + "字节");
        }
        this.length = length;
        D = d;
    }

    /**
     * 设置密钥长度 256/512
     *
     * @param length 密钥长度 必须是256或者512
     */
    public void setLength(int length) {
        if (length != 256 && length != 512) {
            throw new IllegalArgumentException("SM2PriKey长度(length)必须是256或者512,当前长度为:" + length + "位");
        }
        this.length = length;
    }

    /**
     * 设置私钥D  d必须位32或者64个字节
     *
     * @param d 私钥D
     */
    public void setD(byte[] d) {
        if (d.length != 32 && d.length != 64) {
            throw new IllegalArgumentException("SM2PriKey-D数组长度必须位32或者64字节,当前长度为:" + d.length + "字节");
        }
        this.length = d.length * 8;
        D = d;
    }


    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append("    |    project    |   value  ").append(nl);
        buf.append("   _|_______________|______________________________________________________").append(nl);
        buf.append("   1| bits          | ").append(this.length).append(nl);
        buf.append("   2| D             | ").append(BytesOperate.bytesToHexString(this.D)).append(nl);
        return buf.toString();
    }

    @Override
    public String getAlgorithm() {
        return "SM2PriKey";
    }

    @Override
    public byte[] encode() {
        BytesBuffer buf = new BytesBuffer();
        buf.append(BytesOperate.int2bytes(this.length));
        buf.append(this.D);
        return buf.toBytes();
    }

    @Override
    public void decode(byte[] encodedKey) {
        //todo 因为返回实际是64字节,长度字段却是0100(256位)
        this.length = BytesOperate.bytes2int(encodedKey, 0)+256;
        this.D = new byte[this.length / 8];
        //从encodedKey的第4个字节开始  复制到this.D的0位置 复制长度为this.length/8
        System.arraycopy(encodedKey, 4, this.D, 0, this.length / 8);
    }

    //size
    public int size() {
        return 4 + this.length / 8;
    }


    /**
     * 转换为256位
     *
     * @return SM2PriKey
     */
    public SM2PrivateKey to256() {
        if (this.length == 256) {
            return this;
        }
        byte [] D = new byte[32];
        System.arraycopy(this.D, 32, D, 0, D.length);
        return new SM2PrivateKey(256, D);
    }

    /**
     * 转换为512位
     *
     * @return SM2PriKey
     */
    public SM2PrivateKey to512() {
        if (this.length == 512) {
            return this;
        }
        byte[] d = new byte[64];
        System.arraycopy(D, 0, d, 32, D.length);
        return new SM2PrivateKey(512, d);
    }
}
