package com.af.device.impl;

import com.af.device.DeviceInfo;
import com.af.device.IAFDevice;
import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/16 9:12
 */
public class AFSVDevice  implements IAFDevice {

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * @throws AFCryptoException 获取设备信息异常
     */
    @Override
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        return null;
    }

    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * @throws AFCryptoException 获取随机数异常
     */
    @Override
    public byte[] getRandom(int length) throws AFCryptoException {
        return new byte[0];
    }
}
