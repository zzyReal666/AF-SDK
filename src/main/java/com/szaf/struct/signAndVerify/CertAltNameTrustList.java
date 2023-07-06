package com.szaf.struct.signAndVerify;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/16 10:37
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CertAltNameTrustList {

    private byte[] certList;
    private int number;

}
