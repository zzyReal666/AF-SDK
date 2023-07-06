package com.szaf.crypto.key.sm2;

import com.szaf.crypto.key.Key;
import com.szaf.utils.BytesBuffer;
import com.szaf.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description SM2公钥 256位或512位
 * @since 2023/4/26 10:49
 */
@Getter
@Setter
@NoArgsConstructor
public class SM2PublicKey implements Key {

    private int length; //  256/512 模长
    private byte[] x = new byte[64];   //公钥x
    private byte[] y = new byte[64];   //公钥y

    //构造函数 字节数据
    public SM2PublicKey(byte[] data) {
        this.decode(data);
    }

    public SM2PublicKey(int length) {
        this.length = length;
        this.x = new byte[length / 8];
        this.y = new byte[length / 8];
    }


    //构造函数 全部参数
    public SM2PublicKey(int length, byte[] x, byte[] y) {
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
        builder.append("   4| y             | ").append(BytesOperate.bytesToHexString(this.y)).append(nl);
        return builder.toString();
    }

    @Override
    public String getAlgorithm() {
        return "SM2PubKey";
    }

    public byte[] encode() {
        return new BytesBuffer()
                .append(256)
                .append(this.x)
                .append(this.y)
                .toBytes();
    }

    @Override
    public void decode(byte[] pubKey) {
        this.length = BytesOperate.bytes2int(pubKey, 0);
        System.arraycopy(pubKey, 4, this.x, 0, this.x.length);
        System.arraycopy(pubKey, 4 + this.x.length, this.y, 0, this.y.length);
    }

    public int size() {
        return 4 + this.x.length + this.y.length;
    }


    /**
     * 256位转512位 前32个字节补0
     *
     * @return 512位公钥
     */
    public SM2PublicKey to512() {
        if (this.length == 512) {
            return this;
        } else if (this.length == 256) {
            byte[] x512 = new byte[64];
            byte[] y512 = new byte[64];
            System.arraycopy(this.x, 0, x512, 32, 32);
            System.arraycopy(this.y, 0, y512, 32, 32);
            return new SM2PublicKey(512, x512, y512);
        } else {
            throw new RuntimeException("SM2PubKey length error");
        }

    }

    /**
     * 512位转256位 取后32个字节
     *
     * @return 256位公钥
     */
    public SM2PublicKey to256() {
        if (this.length == 256) {
            return this;
        } else if (this.length == 512) {
            byte[] x256 = new byte[32];
            byte[] y256 = new byte[32];
            System.arraycopy(this.x, 32, x256, 0, 32);
            System.arraycopy(this.y, 32, y256, 0, 32);
            return new SM2PublicKey(256, x256, y256);
        } else {
            throw new RuntimeException("SM2PubKey length error");
        }

    }
}
