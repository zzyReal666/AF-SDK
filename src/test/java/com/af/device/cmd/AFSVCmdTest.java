package com.af.device.cmd;

import com.af.device.impl.AFSVDevice;
import org.junit.jupiter.api.Test;

class AFSVCmdTest {
    static AFSVDevice device = AFSVDevice.getInstance("192.168.1.224", 8008, "abcd1234");


    @Test
    void testValidateCertificate() {
    }

}