package com.af.struct.impl.RSA;

import com.af.utils.BytesBuffer;
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

    public void decode(byte[] data) {
        BytesBuffer buffer = new BytesBuffer(data);
        this.pubKey = new RSAPubKey(buffer.readOneData());
        this.priKey = new RSAPriKey(buffer.readOneData());
    }

    public String toString() {
        return "ECCKeyPair\n" + this.pubKey + "\n" + this.priKey;
    }
}
