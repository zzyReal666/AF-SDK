package com.af.struct.signAndVerify;

import lombok.*;

import static cn.hutool.core.util.ByteUtil.bytesToInt;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AFSvCryptoInstance {
    public byte[] policyName;
    public int keyIndex;  //密钥索引
    public int keyType;   //密钥类型
    public int policy;   //策略 该参数无用，兼容以前版本



}



