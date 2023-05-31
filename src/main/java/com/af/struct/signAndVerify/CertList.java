package com.af.struct.signAndVerify;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/28 15:17
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CertList {

    private byte[] certData; //证书数据 DER编码
    private int certCount;
}
