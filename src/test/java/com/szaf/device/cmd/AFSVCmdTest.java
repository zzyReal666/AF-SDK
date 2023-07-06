package com.szaf.device.cmd;

import com.szaf.device.impl.AFSVDevice;
import org.junit.jupiter.api.Test;

class AFSVCmdTest {
    static AFSVDevice device = AFSVDevice.getInstance("192.168.1.224", 8008, "abcd1234");


    @Test
    void testValidateCertificate() {
    }

}