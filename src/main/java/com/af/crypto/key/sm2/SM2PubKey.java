package com.af.crypto.key.sm2;

import com.af.constant.SM2KeyType;
import com.af.crypto.key.Key;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.nio.ByteBuffer;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description SM2公钥 256位或512位
 * @since 2023/4/26 10:49
 */
@Setter
@Getter
@NoArgsConstructor
public class SM2PubKey implements Key {

    private SM2KeyType keyType; //密钥类型 签名/加密
    private int length; //密钥长度 256/512
    private byte[] x;   //公钥x
    private byte[] y;   //公钥y

    //构造函数 全部参数
    public SM2PubKey(int length, byte[] x, byte[] y) {
        //如果密钥长度不是256或512位 抛出异常
        if (length != 256 && length != 512) {
            throw new IllegalArgumentException("SM2PubKey length must be 256 or 512");
        }
        //如果x和y长度不等
        if (x.length != y.length) {
            throw new IllegalArgumentException("SM2PubKey x and y length must be equal");
        }
        //如果length != x.length/8
        if (length != x.length * 8) {
            throw new IllegalArgumentException("SM2PubKey length must be equal to x.length * 8");
        }
        this.length = length;
        this.x = x;
        this.y = y;

    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        String nl = System.getProperty("line.separator");
        builder.append("    |    project    |   value  ").append(nl);
        builder.append("   _|_______________|______________________________________________________").append(nl);
        builder.append("   1| bits          | ").append(this.length).append(nl);
        builder.append("   2| x             | ").append(BytesOperate.bytesToHexString(this.x)).append(nl);
        builder.append("   3| y             | ").append(BytesOperate.bytesToHexString(this.y)).append(nl);
        return builder.toString();
    }

    @Override
    public String getAlgorithm() {
        return "SM2PubKey";
    }

    public byte[] encode() {
        ByteBuffer buffer = ByteBuffer.allocate(4 + this.x.length + this.y.length);
        buffer.put(BytesOperate.int2bytes(this.length));
        buffer.put(this.x);
        buffer.put(this.y);
        return buffer.array();
    }

    @Override
    public void decode(byte[] pubKey) {
        this.length = BytesOperate.bytes2int(pubKey, 0);
        System.arraycopy(pubKey, 4, this.x, 0, this.x.length / 8);
        System.arraycopy(pubKey, 4 + this.x.length / 8, this.y, 0, this.y.length / 8);
    }

    //size
    public int size() {
        return 4 + this.x.length / 8 + this.y.length / 8;
    }


    /**
     * 256位转512位 前32个字节补0
     *
     * @return 512位公钥
     */
    public SM2PubKey to512() {
        if (this.length == 512) {
            return this;
        }
        byte[] x512 = new byte[64];
        byte[] y512 = new byte[64];
        System.arraycopy(this.x, 0, x512, 32, 32);
        System.arraycopy(this.y, 0, y512, 32, 32);
        return new SM2PubKey(512, x512, y512);
    }

    /**
     * 512位转256位 取后32个字节
     *
     * @return 256位公钥
     */
    public SM2PubKey to256() {
        if (this.length == 256) {
            return this;
        }
        byte[] x256 = new byte[32];
        byte[] y256 = new byte[32];
        System.arraycopy(this.x, 32, x256, 0, 32);
        System.arraycopy(this.y, 32, y256, 0, 32);
        return new SM2PubKey(256, x256, y256);
    }
}
