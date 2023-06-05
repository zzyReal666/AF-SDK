package com.af.crypto.key.sm2;

import cn.hutool.core.util.ArrayUtil;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
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


    private int length; //密钥长度 256/512
    //公钥
    private SM2PublicKey pubKey;
    //私钥
    private SM2PrivateKey priKey;


    public void decode(byte[] data) {
        BytesBuffer buffer = new BytesBuffer(data);

        //公钥
        byte[] pubKey = buffer.readOneData();
        //公钥前加上公钥长度的小端序,4个字节
        byte[] len = BytesOperate.int2bytes(pubKey.length);
        //合并数组
        this.pubKey = new SM2PublicKey(ArrayUtil.addAll(len, pubKey));

        //私钥
        byte[] priKey = buffer.readOneData();
        //私钥前加上私钥长度的小端序,4个字节
        len = BytesOperate.int2bytes(priKey.length);
        //合并数组
        this.priKey = new SM2PrivateKey(ArrayUtil.addAll(len, priKey));
    }


    public SM2KeyPair to256() {
        return new SM2KeyPair(256, pubKey.to256(), priKey.to256());
    }

    public SM2KeyPair to512() {
        return new SM2KeyPair(512, pubKey.to512(), priKey.to512());
    }
}
