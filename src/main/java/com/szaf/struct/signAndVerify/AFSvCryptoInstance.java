package com.szaf.struct.signAndVerify;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AFSvCryptoInstance {
    public String policyName; //应用实体名称
    public int keyIndex;  //密钥索引
    public int keyType;   //密钥类型 3:SM2 4:RSA
    public int policy;   //策略 该参数无用，兼容以前版本
}



