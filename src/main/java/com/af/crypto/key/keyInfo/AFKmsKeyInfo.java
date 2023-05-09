package com.af.crypto.key.keyInfo;

import com.af.constant.ConstantNumber;
import com.af.utils.BytesOperate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 密钥信息 包含密钥类型、密钥长度、密钥对 、对称密钥
 * @since 2023/4/18 11:49
 */
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class AFKmsKeyInfo {

    /**
     * 密钥类型
     */
    private int keyType;
    /**
     * 密钥长度
     */
    private int keyBits;
    /**
     * 对称密钥
     */
    private byte[] symmetricData;
    /**
     * 非对称/密钥对
     */
    private AFByteKeyPair keyPair;

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append("    |    project        |   value  ").append(nl);
        buf.append("   _|___________________|______________________________________________________").append(nl);
        buf.append("   1| type              | ").append(this.keyType).append(nl);
        buf.append("   2| bits              | ").append(this.keyBits).append(nl);
        if (this.keyType == ConstantNumber.KEY_TYPE_KEK) {
            buf.append("   3| symmetricKeyData  | ").append(BytesOperate.bytesToHexString(this.symmetricData)).append(nl);
        } else {
            buf.append("   3| keyPairData-pub   | ").append(BytesOperate.bytesToHexString(this.keyPair.getPubKeyData())).append(nl);
            buf.append("   4| keyPairData-prv   | ").append(BytesOperate.bytesToHexString(this.keyPair.getPriKeyData())).append(nl);
        }
        return buf.toString();
    }
}
