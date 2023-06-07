package com.af.crypto.key.sm2;


import com.af.crypto.key.Key;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description SM2私钥
 * @since 2023/4/26 16:52
 */
@Getter
@Setter
@NoArgsConstructor
public class SM2PrivateKey implements Key {

    private int length; //模长 恒为256
    private byte[] D = new byte[64];   //私钥D

    public SM2PrivateKey(byte[] data) {
        this.decode(data);
    }

    public SM2PrivateKey(int length, byte[] d) {
        D = d;
    }

    /**
     * 设置密钥长度 256/512
     *
     * @param length 密钥长度 必须是256或者512
     */
    public void setLength(int length) {
        this.length = length;
    }

    /**
     * 设置私钥D  d必须位32或者64个字节
     *
     * @param d 私钥D
     */
    public void setD(byte[] d) {
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
        buf.append(256);
        buf.append(this.D);
        return buf.toBytes();
    }

    @Override
    public void decode(byte[] encodedKey) {
        //传入字节生成 不带长度 4+n 只有n
        if (encodedKey.length == 32) {
            this.length = 256;
            System.arraycopy(encodedKey, 0, this.D, 0, EXP_ECCref_MAX_LEN);
        }
        //网络通信返回
        this.length = BytesOperate.bytes2int(encodedKey, 0);
        this.D = new byte[64];
        System.arraycopy(encodedKey, 4, this.D, 0, this.D.length);
    }

    //size
    public int size() {
        return 4 + this.D.length;
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
        byte[] D = new byte[32];
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
        return new SM2PrivateKey(256, d);
    }
}
