package com.szaf.struct.signAndVerify.RSA;

import lombok.*;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/6/9 10:39
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class RSAKeyPairStructure {
    private byte[] pubKey;
    private byte[] priKey;
}
