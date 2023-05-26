package com.af.struct.signAndVerify;

import com.af.utils.BytesOperate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/16 10:30
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AFSM2DecodeSignedAndEnvelopedData {


    private byte[] data;
    private byte[] signerCertificate;
    private int digestAlgorithm;


    public String toString() {
        StringBuilder builder = new StringBuilder();
        String nl = System.getProperty("line.separator");
        builder.append("    |    project            |   value  ").append(nl);
        builder.append("   _|_______________________|______________________________________________________").append(nl);
        builder.append("   1| data                  | ").append(BytesOperate.bytesToHexString(this.data)).append(nl);
        builder.append("   2| signerCertificate     | ").append(new String(this.signerCertificate)).append(nl);
        builder.append("   3| digestAlgorithm       | ").append(this.digestAlgorithm).append(nl);
        return builder.toString();
    }
}
