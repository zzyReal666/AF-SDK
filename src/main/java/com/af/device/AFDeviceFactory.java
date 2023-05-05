package com.af.device;

import com.af.device.impl.AFHsmDevice;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 设备工厂
 * @since 2023/4/27 14:38
 */
public class AFDeviceFactory {


  //工厂模式获取AFHsmDevice 单例
    public static AFHsmDevice getAFHsmDevice() {
        return new AFHsmDevice();
    }


}
