package com.af.bean;

import org.junit.jupiter.api.Test;

class RequestMessageTest {
    @Test
    void testObject() {
        RequestMessage requestMessage = new RequestMessage(1, new byte[]{1, 2, 3});
        System.out.println(requestMessage);
    }

    @Test
    void testToBytes() {
        RequestMessage requestMessage = new RequestMessage(1, new byte[]{1, 2, 3});
        byte[] bytes = requestMessage.encode();
        //遍历数组
        for (byte b : bytes) {
            System.out.println(b);
        }
    }
}