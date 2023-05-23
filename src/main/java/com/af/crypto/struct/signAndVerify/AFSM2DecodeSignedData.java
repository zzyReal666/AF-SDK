package com.af.crypto.struct.signAndVerify;

import lombok.Getter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/16 10:31
 */
@Getter
public class AFSM2DecodeSignedData extends AFSM2DecodeSignedAndEnvelopedData {
    private byte[] signedData;


    public AFSM2DecodeSignedData(byte[] signedData) {
        this.signedData = signedData;
    }

    public AFSM2DecodeSignedData(byte[] data, byte[] signerCertificate, int digestAlgorithm, byte[] signedData) {
        super(data, signerCertificate, digestAlgorithm);
        this.signedData = signedData;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        String nl = System.getProperty("line.separator");
        builder.append("    |    project            |   value  ").append(nl);
        builder.append("   _|_______________________|______________________________________________________").append(nl);
        builder.append("   1| signedData            | ").append(new String(signedData)).append(nl);
        return builder.toString() + super.toString();
    }

}
