package com.af.crypto.struct.implold;

import com.af.exception.AFCryptoException;
import com.af.crypto.struct.IAFStruct;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 11:06
 */
@Getter
@Setter
@NoArgsConstructor
public class DeviceInfo implements IAFStruct {
    private byte[] IssuerName = new byte[40];
    private byte[] DeviceName = new byte[16];
    private byte[] DeviceSerial = new byte[16];
    private int DeviceVersion;
    private int StandardVersion;
    private int[] AsymAlgAbility = new int[2];
    private int SymAlgAbility;
    private int HashAlgAbility;
    private int BufferSize;

    @Override
    public int size() {
        return 0;
    }

    @Override
    public void decode(byte[] deviceData) throws AFCryptoException {
        System.arraycopy(deviceData, 0, this.IssuerName, 0, 40);
        System.arraycopy(deviceData, 40, this.DeviceName, 0, 16);
        System.arraycopy(deviceData, 40 + 16, this.DeviceSerial, 0, 16);

        this.DeviceVersion = BytesOperate.bytes2int(deviceData, 40 + 16 + 16);
        this.StandardVersion = BytesOperate.bytes2int(deviceData, 40 + 16 + 16 + 4);
        this.AsymAlgAbility[0] = BytesOperate.bytes2int(deviceData, 40 + 16 + 16 + 4 + 4);
        this.AsymAlgAbility[1] = BytesOperate.bytes2int(deviceData, 40 + 16 + 16 + 4 + 4 + 4);
        this.SymAlgAbility = BytesOperate.bytes2int(deviceData, 40 + 16 + 16 + 4 + 4 + 4 + 4);
        this.HashAlgAbility = BytesOperate.bytes2int(deviceData, 40 + 16 + 16 + 4 + 4 + 4 + 4 + 4);
        this.BufferSize = BytesOperate.bytes2int(deviceData, 40 + 16 + 16 + 4 + 4 + 4 + 4 + 4 + 4);
    }

    @Override
    public byte[] encode() {
        return null;
    }


    @Override
    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("    |    project          |   value  ").append(nl);
        buf.append("   _|_____________________|______________________________________________________").append(nl);
        buf.append("   1| issuerName          | ").append(new String(this.IssuerName)).append(nl);
        buf.append("   2| Device name         | ").append(new String(this.DeviceName)).append(nl);
        buf.append("   3| Serial number       | ").append(new String(this.DeviceSerial)).append(nl);
        buf.append("   4| Device version      | ").append("v" + this.toHexString(this.DeviceVersion)).append(nl);
        buf.append("   5| Standard version    | ").append("v" + this.toHexString(this.StandardVersion)).append(nl);
        buf.append("   6| Public key algorithm| ").append(this.toHexString(this.AsymAlgAbility[0]) + " | " + this.toHexString(this.AsymAlgAbility[1])).append(nl);
        buf.append("   7| Symmetric algorithm | ").append(this.toHexString(this.SymAlgAbility)).append(nl);
        buf.append("   8| Hash algorithm      | ").append(this.toHexString(this.HashAlgAbility)).append(nl);
        buf.append("   9| User memory space   | ").append(this.BufferSize / 1024 + "KB").append(nl);
        return buf.toString();
    }

    /**
     * 将int转换为16进制字符串 0x00000000
     *
     * @param n int参数
     * @return 16进制字符串
     */
    private String toHexString(int n) {
        String code = Integer.toHexString(n);

        for (int i = code.length(); i < 8; ++i) {
            code = "0" + code;
        }
        return "0x" + code;
    }
}
