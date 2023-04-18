package com.af.crypto.key;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 对称密钥状态
 * @since 2023/4/18 11:47
 */
@Data  // 生成get set方法
@AllArgsConstructor // 生成全参构造方法
public class AFSymmetricKeyStatus {
    private int index;
    private int length;
}
