package com.szaf.device;

import com.szaf.utils.BytesOperate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 设备信息
 * @since 2023/5/5 14:53
 */
@Getter
@Setter
@NoArgsConstructor

public class DeviceInfo {
    private byte[] IssuerName = new byte[40];
    private byte[] DeviceName = new byte[16];
    private byte[] DeviceSerial = new byte[16];
    private int DeviceVersion;
    private int StandardVersion;
    private int[] AsymAlgAbility = new int[2];
    private int SymAlgAbility;
    private int HashAlgAbility;
    private int BufferSize;


    public void decode(byte[] deviceData) {
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

    public byte[] encode() {
        //decode 的反向操作
        byte[] deviceData = new byte[40 + 16 + 16 + 4 + 4 + 4 + 4 + 4 + 4 + 4];
        System.arraycopy(this.IssuerName, 0, deviceData, 0, 40);
        System.arraycopy(this.DeviceName, 0, deviceData, 40, 16);
        System.arraycopy(this.DeviceSerial, 0, deviceData, 40 + 16, 16);
        System.arraycopy(BytesOperate.int2bytes(this.DeviceVersion), 0, deviceData, 40 + 16 + 16, 4);
        System.arraycopy(BytesOperate.int2bytes(this.StandardVersion), 0, deviceData, 40 + 16 + 16 + 4, 4);
        System.arraycopy(BytesOperate.int2bytes(this.AsymAlgAbility[0]), 0, deviceData, 40 + 16 + 16 + 4 + 4, 4);
        System.arraycopy(BytesOperate.int2bytes(this.AsymAlgAbility[1]), 0, deviceData, 40 + 16 + 16 + 4 + 4 + 4, 4);
        System.arraycopy(BytesOperate.int2bytes(this.SymAlgAbility), 0, deviceData, 40 + 16 + 16 + 4 + 4 + 4 + 4, 4);
        System.arraycopy(BytesOperate.int2bytes(this.HashAlgAbility), 0, deviceData, 40 + 16 + 16 + 4 + 4 + 4 + 4 + 4, 4);
        System.arraycopy(BytesOperate.int2bytes(this.BufferSize), 0, deviceData, 40 + 16 + 16 + 4 + 4 + 4 + 4 + 4 + 4, 4);
        return deviceData;

    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        String nl = System.getProperty("line.separator");
        builder.append("    |    project          |   value  ").append(nl);
        builder.append("   _|_____________________|______________________________________________________").append(nl);
        builder.append("   1| issuerName          | ").append(new String(this.IssuerName)).append(nl);
        builder.append("   2| Device name         | ").append(new String(this.DeviceName)).append(nl);
        builder.append("   3| Serial number       | ").append(new String(this.DeviceSerial)).append(nl);
        builder.append("   4| Device version      | ").append("v" + this.toHexString(this.DeviceVersion)).append(nl);
        builder.append("   5| Standard version    | ").append("v" + this.toHexString(this.StandardVersion)).append(nl);
        builder.append("   6| Public key algorithm| ").append(this.toHexString(this.AsymAlgAbility[0]) + " | " + this.toHexString(this.AsymAlgAbility[1])).append(nl);
        builder.append("   7| Symmetric algorithm | ").append(this.toHexString(this.SymAlgAbility)).append(nl);
        builder.append("   8| Hash algorithm      | ").append(this.toHexString(this.HashAlgAbility)).append(nl);
        builder.append("   9| User memory space   | ").append(this.BufferSize / 1024 + "KB").append(nl);
        return builder.toString();
    }


    private String toHexString(int n) {
        StringBuilder code = new StringBuilder(Integer.toHexString(n));

        for (int i = code.length(); i < 8; ++i) {
            code.insert(0, "0");
        }

        return "0x" + code;
    }

}