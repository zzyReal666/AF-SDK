package com.af.struct.signAndVerify;

import lombok.NoArgsConstructor;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/16 10:28
 */
@NoArgsConstructor
public class AFPkcs7DecodeDigestData extends AFPkcs7DecodeData{

    public AFPkcs7DecodeDigestData(byte[] data, byte[] signedData) {
        super(data, null, 0, signedData);
    }

}
