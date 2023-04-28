package com.af.netty;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class AFNettyClientTest {
    @Test
    void test() throws Exception {
        AFNettyClient client = AFNettyClient.getInstance("192.168.1.224", 8008,"abcd1234");
        //连接
        int len = 60;
        int version = 0x01000000;
        int sessionID = 0x00000000;

        byte[] psw = "abcd1234".getBytes();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(psw);
        for (int i = psw.length; i < 16; ++i) {
            out.write(0);
        }

        byte[] data = out.toByteArray();
        System.out.println(data.toString());
        RequestMessage requestMessage = new RequestMessage(0x00000000, data);
        byte[] send = client.send(requestMessage.encode());
        System.out.println(send.length);
        System.out.println(new ResponseMessage(send));

    }


    /**
     * 请求随机数
     *
     * @throws Exception
     */
    @Test
    void test2() throws Exception {
        AFNettyClient client = AFNettyClient.getInstance("192.168.1.224", 8008,"abcd1234");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(8).array());

        RequestMessage requestMessage = new RequestMessage(0x00020002, out.toByteArray());
        byte[] send = client.send(requestMessage.encode());
        System.out.println(send.length);
        System.out.println(new ResponseMessage(send));

//        System.out.println("=====================================");
//        AFNettyClient client2 = AFNettyClient.getInstance("192.168.1.224", 8008,"abcd1234");
//        ByteArrayOutputStream out2 = new ByteArrayOutputStream();
//        out2.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(16).array());
//
//        RequestMessage requestMessage2 = new RequestMessage(0x00020002, out2.toByteArray());
//        byte[] send2 = client2.send(requestMessage2.encode());
//        System.out.println(send2.length);
//        System.out.println(new ResponseMessage(send2));

    }

    @Test
    void test3() throws Exception {
        AFNettyClient client = AFNettyClient.getInstance("192.168.1.224", 8008,"abd1234");


    }
}