package com.af.device.impl;

import com.af.crypto.algorithm.sm1.IAFSM1;
import com.af.crypto.algorithm.sm2.IAFSM2;
import com.af.crypto.algorithm.sm4.IAFSM4;
import com.af.netty.AFNettyClient;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description  HSM设备实现类 用于实现HSM设备的各种算法
 * @since 2023/4/27 14:53
 */
public class AFHsmDeviceImpl  {
    private AFNettyClient nettyClient; //netty客户端
    private IAFSM1 sm1;
    private IAFSM2 sm2;
    private IAFSM4 sm3;
    private IAFSM4 sm4;





}
