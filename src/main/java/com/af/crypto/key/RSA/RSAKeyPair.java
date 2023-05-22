package com.af.crypto.key.RSA;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class RSAKeyPair {
    private RSAPublicKey pubKey;
    private RSAPrivateKey priKey;
    public String toString() {
        return "ECCKeyPair\n" + this.pubKey + "\n" + this.priKey;
    }
}
