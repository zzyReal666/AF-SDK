package com.af.device.impl;

import com.af.device.AFDeviceFactory;
import com.af.device.DeviceInfo;
import org.junit.jupiter.api.Test;

import java.util.Arrays;


class
AFSVDeviceTest {

    static AFSVDevice device = AFDeviceFactory.getAFSVDevice("192.168.1.224", 8008, "abcd1234");

    @Test
    void testGetRandom() throws Exception {

        DeviceInfo deviceInfo = device.getDeviceInfo();
        System.out.println(deviceInfo);
        byte[] random = device.getRandom(5);
        System.out.println(Arrays.toString(random));

    }
}