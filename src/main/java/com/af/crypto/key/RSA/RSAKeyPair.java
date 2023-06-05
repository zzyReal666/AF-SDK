package com.af.crypto.key.RSA;

import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class RSAKeyPair {
    private RSAPubKey pubKey;
    private RSAPriKey priKey;


    public RSAKeyPair(byte[] data) {
        this.decode(data);
    }

    //decode
    public void decode(byte[] data) {

        BytesBuffer buffer = new BytesBuffer(data);
        //公钥
        byte[] pubKey = buffer.readOneData();
        //公钥前加上4个字节的长度,数值为pubKey长度的小端序
        byte[] pubKeyData = new byte[pubKey.length + 4];
        byte[] len = BytesOperate.int2bytes(pubKey.length);
        System.arraycopy(len, 0, pubKeyData, 0, 4);
        System.arraycopy(pubKey, 0, pubKeyData, 4, pubKey.length);
        this.pubKey = new RSAPubKey(pubKeyData);

        //私钥
        byte[] priKey = buffer.readOneData();
        //私钥前加上4个字节的长度,数值为priKey长度的小端序
        byte[] priKeyData = new byte[priKey.length + 4];
        len = BytesOperate.int2bytes(priKey.length);
        System.arraycopy(len, 0, priKeyData, 0, 4);
        System.arraycopy(priKey, 0, priKeyData, 4, priKey.length);
        this.priKey = new RSAPriKey(priKeyData);

    }






    public String toString() {
        return "ECCKeyPair\n" + this.pubKey + "\n" + this.priKey;
    }
}
