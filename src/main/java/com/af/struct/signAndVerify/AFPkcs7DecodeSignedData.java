package com.af.struct.signAndVerify;

import lombok.NoArgsConstructor;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/16 10:35
 */
@NoArgsConstructor
public class AFPkcs7DecodeSignedData extends AFPkcs7DecodeData {


    public AFPkcs7DecodeSignedData(byte[] data, byte[] signerCertificate, int digestAlgorithm, byte[] signedData) {
        super(data, signerCertificate, digestAlgorithm, signedData);
    }
}
