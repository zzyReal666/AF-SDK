package com.af.struct.signAndVerify;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AFSvCryptoInstance {
    public byte[] policyName;
    public int keyIndex;
    public int keyType;
    public int policy;


}
