package com.af.device;

import com.af.device.impl.AFHsmDevice;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AFDeviceFactoryTest {

    static AFHsmDevice device;



    @Test
    void testGetAFHsmDevice() throws Exception {
        System.out.println(device);
    }
}