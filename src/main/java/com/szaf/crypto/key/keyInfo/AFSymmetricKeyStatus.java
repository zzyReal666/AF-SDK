package com.szaf.crypto.key.keyInfo;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 对称密钥状态
 * @since 2023/4/18 11:47
 */

@Data
@AllArgsConstructor
public class AFSymmetricKeyStatus {
    private int index;
    private int length;
}
