package com.af.device.impl;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.HexUtil;
import com.af.constant.Algorithm;
import com.af.constant.TSMInfoFlag;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

class AFTSDeviceTest {
    //    static AFTSDevice device = AFDeviceFactory.getAFTSDevice("192.168.10.40", 8011, "abcd1234");
    static AFTSDevice device = new AFTSDevice.Builder("192.168.10.40", 8011, "abcd1234").build();

    final byte[] data = "af/tsa-时间戳测试".getBytes(StandardCharsets.UTF_8);

    //证书路径
    static String deviceCertFile = "D:\\workPlace\\Sazf_SDK\\src\\test\\resources\\device.cer";
    //证书
    static byte[] deviceCert = FileUtil.readBytes(deviceCertFile);


    @Test
    void testTsRequestAndResponse() throws Exception {


        //时间戳请求并响应 不携带证书
        byte[] bytes = device.tsRequestAndResponse(data, 1);
        System.out.println(HexUtil.encodeHexStr(bytes));

        //时间戳请求并响应 携带证书
        byte[] bytes1 = device.tsRequestAndResponse(data, 0);
        System.out.println(HexUtil.encodeHexStr(bytes1));


        //验证时间戳信息 不携带证书
        boolean b = device.tsVerify(bytes, Algorithm.SGD_SM2_1.getValue(), deviceCert);
        System.out.println("不携带证书验证:" + b);

        //验证时间戳信息 携带证书
        boolean b1 = device.tsVerify(bytes1, Algorithm.SGD_SM2_1.getValue(), null);
        System.out.println("携带证书验证:" + b1);


    }

    //获取时间戳信息
    @Test
    void testTsRequest() throws Exception {
        //时间戳请求并响应 不携带证书
        byte[] bytes = device.tsRequestAndResponse(data, 1);
        System.out.println(HexUtil.encodeHexStr(bytes));

        //时间戳请求并响应 携带证书
        byte[] bytes1 = device.tsRequestAndResponse(data, 0);
        System.out.println(HexUtil.encodeHexStr(bytes1));

        //获取时间戳信息
        String tsInfo = device.getTsInfo(bytes);
        System.out.println("不携带证书获取时间戳信息:" + tsInfo);


        String tsInfo1 = device.getTsInfo(bytes1);
        System.out.println("携带证书获取时间戳信息:" + tsInfo1);


    }

    //获取时间戳详细信息
    @Test
    void testTsRequest1() throws Exception {
        //时间戳请求并响应 不携带证书
        byte[] bytes = device.tsRequestAndResponse(data, 1);
        System.out.println(HexUtil.encodeHexStr(bytes));

        //时间戳请求并响应 携带证书
        byte[] bytes1 = device.tsRequestAndResponse(data, 0);
        System.out.println(HexUtil.encodeHexStr(bytes1));

     

        //遍历TSMInfoFlag
        for (TSMInfoFlag value : TSMInfoFlag.values()) {
            byte[] tsDetailInfo1 = device.getTsDetailInfo(bytes1, value);
            System.out.println("携带证书获取时间戳详细信息:" + HexUtil.encodeHexStr(tsDetailInfo1));
        }

    }


}