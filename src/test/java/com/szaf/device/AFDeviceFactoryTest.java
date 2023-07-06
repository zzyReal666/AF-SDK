package com.szaf.device;

import com.szaf.device.impl.AFHsmDevice;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AFDeviceFactoryTest {

    static AFHsmDevice device;

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        device = AFDeviceFactory.getAFHsmDevice("192.168.1.224", 8008, "abcd1234");
    }

    @Test
    void testGetAFHsmDevice() throws Exception {
        System.out.println(device);
    }
}