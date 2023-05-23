package com.af.device.impl;

import cn.hutool.core.util.HexUtil;
import com.af.constant.TimeStampAlg;
import com.af.device.AFDeviceFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

class AFTSDeviceTest {
    static AFTSDevice device;
    final byte[] data = "af/tsa-时间戳测试".getBytes(StandardCharsets.UTF_8);


    @BeforeEach
    void setUp() {
        device = AFDeviceFactory.getAFTSDevice("192.168.20.50", 8008, "abcd1234");

    }

    @Test
    void testGetTimeStamp() throws Exception {
        System.out.println(device);
    }

    @Test
    void testTsRequestAndResponse() throws Exception {
        byte[] ts = device.tsRequestAndResponse(data, null, 0, TimeStampAlg.SGD_SM3, TimeStampAlg.SGD_SM2);
        System.out.println("时间戳请求结果：" + HexUtil.encodeHexStr(ts));
        System.out.println("时间戳验证结果：" + device.tsVerify(ts, TimeStampAlg.SGD_SM3, TimeStampAlg.SGD_SM2, null));

    }


    @Test
    void testTsVerify() throws Exception {

    }

    @Test
    void testKeyAgreement() throws Exception {
        byte[] bytes = device.keyAgreement(AFTSDevice.getClient());
        System.out.println(HexUtil.encodeHexStr(bytes));

    }

}