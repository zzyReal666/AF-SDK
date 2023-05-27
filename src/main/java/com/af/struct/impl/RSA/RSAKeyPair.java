package com.af.struct.impl.RSA;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class RSAKeyPair {
    private RSAPubKey pubKey;
    private RSAPriKey priKey;
    public String toString() {
        return "ECCKeyPair\n" + this.pubKey + "\n" + this.priKey;
    }
}
