package com.af.device;

import com.af.device.impl.AFHsmDevice;
import com.af.device.impl.AFSVDevice;
import com.af.device.impl.AFTSDevice;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 设备工厂 用于获取密码机设备
 * @since 2023/4/27 14:38
 */
public class AFDeviceFactory {


    //密码机
    public static AFHsmDevice getAFHsmDevice(String host, int port, String passwd) {
        return AFHsmDevice.getInstance(host, port, passwd);
    }



    //时间戳服务器
    public static AFTSDevice getAFTSDevice(String host, int port, String passwd) {
        return AFTSDevice.getInstance(host, port, passwd);
    }


    //签名验签服务器
    public static AFSVDevice getAFSVDevice(String host, int port, String passwd) {
        return AFSVDevice.getInstance(host, port, passwd);
    }



}
