package com.af.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/5 14:59
 */
public enum DeviceType {
    HSM("HSM", 0x01),
    SV("SV", 0x02),
    TS("TS", 0x03);

    private String name;
    private int value;

    DeviceType(String name, int value) {
        this.name = name;
        this.value = value;
    }
}
