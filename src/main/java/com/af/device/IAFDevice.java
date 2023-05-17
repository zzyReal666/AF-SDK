package com.af.device;

import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 设备接口 用于获取密码机的设备信息、随机数、密钥信息等
 * @since 2023/4/18 10:57
 */

public interface IAFDevice {


    //=======================================================设备信息=======================================================

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * @throws AFCryptoException 获取设备信息异常
     */
    DeviceInfo getDeviceInfo() throws AFCryptoException;

    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * @throws AFCryptoException 获取随机数异常
     */
    byte[] getRandom(int length) throws AFCryptoException;








}
