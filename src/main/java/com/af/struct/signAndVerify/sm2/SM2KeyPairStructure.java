package com.af.struct.signAndVerify.sm2;

import lombok.*;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description  sm2密钥对结构体 ASN1编码
 * @since 2023/6/9 10:32
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class SM2KeyPairStructure {
    private byte[] pubKey;
    private byte[] priKey;
}
