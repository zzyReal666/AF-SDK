package com.af.crypto.key.keyInfo;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description   密钥对 公钥 私钥
 * @since 2023/4/18 11:52
 */
@Data
@AllArgsConstructor
public class AFByteKeyPair {
    private byte[] pubKeyData;
    private byte[] priKeyData;
}
