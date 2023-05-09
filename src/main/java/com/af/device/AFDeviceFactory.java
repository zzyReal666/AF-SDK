package com.af.device;

import com.af.device.impl.AFCryptoDevice;
import com.af.device.impl.AFHsmDevice;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 设备工厂 用于获取密码机设备
 * @since 2023/4/27 14:38
 */
public class AFDeviceFactory {


    /**
     * HSM
     *
     * @param host   主机地址
     * @param port   端口
     * @param passwd 密码
     * @return HSM设备
     */
    public static AFHsmDevice getAFHsmDevice(String host, int port, String passwd) {
        return AFHsmDevice.getInstance(host, port, passwd);
    }


    /**
     * Crypto
     *
     * @param host   主机地址
     * @param port   端口
     * @param passwd 密码
     * @return Crypto设备
     */
    public static AFCryptoDevice getAFCryptoDevice(String host, int port, String passwd) {
        return AFCryptoDevice.getInstance(host, port, passwd);
    }


}
