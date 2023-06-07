package com.af.crypto.key.sm2;

import com.af.utils.BytesBuffer;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/26 16:32
 */
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Getter
public class SM2KeyPair {


    private int bits = 256; //模长恒为256
    //公钥
    private SM2PublicKey pubKey;
    //私钥
    private SM2PrivateKey priKey;


    public void decode(byte[] data) {
        BytesBuffer buffer = new BytesBuffer(data);
        this.pubKey = new SM2PublicKey(buffer.readOneData());
        this.priKey = new SM2PrivateKey(buffer.readOneData());
    }


    public SM2KeyPair to256() {
        return new SM2KeyPair(256, pubKey.to256(), priKey.to256());
    }

    public SM2KeyPair to512() {
        return new SM2KeyPair(256, pubKey.to512(), priKey.to512());
    }
}
