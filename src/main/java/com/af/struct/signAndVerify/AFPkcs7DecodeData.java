package com.af.struct.signAndVerify;

import lombok.*;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/16 10:33
 */
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AFPkcs7DecodeData {
    /**
     * 原始数据
     */
    private byte[] data;

    /**
     * 签名者证书
     */
    private byte[] signerCertificate;

    /**
     * HASH算法
     */
    private int digestAlgorithm;

    /**
     * Base64编码的签名值
     */
    private byte[] signedData;
}
