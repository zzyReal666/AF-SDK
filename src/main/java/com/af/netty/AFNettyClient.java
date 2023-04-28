package com.af.netty;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.netty.handler.AFNettyClientHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.logging.LoggingHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/20 10:45
 */


public class AFNettyClient {
    //日志
    private static final Logger logger = LoggerFactory.getLogger(AFNettyClient.class);

    //重试参数
    private static final int MAX_RETRY = 3; // 最大重试次数
    private static final int RETRY_DELAY = 5000; // 重试间隔时间（秒）
    private int retryCount = 0; // 当前重试次数


    //单例
    private static volatile AFNettyClient instance;

    //netty
    private final Bootstrap bootstrap;
    private final String host;
    private final int port;
    private final String password;


    /**
     * 私有构造器
     *
     * @param host 服务器地址
     * @param port 服务器端口
     */
    private AFNettyClient(String host, int port, String password) {
        this.host = host;
        this.port = port;
        this.password = password;
        this.bootstrap = new Bootstrap().group(new NioEventLoopGroup()).channel(NioSocketChannel.class).option(ChannelOption.TCP_NODELAY, true)  //不写缓存
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 7000)  //连接超时时间
                .option(ChannelOption.SO_KEEPALIVE, true); //保持连接
        login();
    }

    /**
     * 获取单例
     *
     * @param host 服务器地址
     * @param port 服务器端口
     * @return 单例 AFNettyClient
     */
    public static AFNettyClient getInstance(String host, int port, String password) {
        if (instance == null) {
            synchronized (AFNettyClient.class) {
                if (instance == null) {
                    instance = new AFNettyClient(host, port, password);
                }
            }
        }
        return instance;
    }

    /**
     * 登录 在获取client实例时自动登录
     */
    private void login() {
        byte[] psw = password.getBytes();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(psw);
        } catch (IOException e) {
            logger.error("密码编码错误!");
            throw new RuntimeException(e);
        }
        for (int i = psw.length; i < 16; ++i) {
            out.write(0);
        }
        new RequestMessage(0x00000000, out.toByteArray());
        ResponseMessage responseMessage = send(new RequestMessage(0x00000000, out.toByteArray()));
        if (responseMessage.getHeader().getErrorCode() != 0x00000000) {
            logger.error("登录失败,请检查密码是否正确!");
            throw new RuntimeException("登录失败,密码错误!");
        }
    }


    /**
     * 发送数据
     *
     * @param data 待发送数据
     * @return 服务器返回数据
     */
    public byte[] send(byte[] data) {
        AFNettyClientHandler handeler = new AFNettyClientHandler(data);
        bootstrap.handler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) throws Exception {
                ch.pipeline().addLast(new LoggingHandler());
                ch.pipeline().addLast(handeler);
            }
        });
        while (retryCount < MAX_RETRY) {
            try {
                ChannelFuture future = bootstrap.connect(host, port).sync();
                logger.info("连接服务器成功，服务器地址{}:{}", host, port);
                future.channel().closeFuture().sync();
                return handeler.getResponse();
            } catch (Exception e) {
                retryCount++;
                logger.error("连接服务器失败，服务器地址：{}:{} ,正在第{}次重试", host, port, retryCount);
                if (retryCount < MAX_RETRY) {
                    long currentTimeMillis = System.currentTimeMillis();
                    while (true) {
                        if (System.currentTimeMillis() - currentTimeMillis >= RETRY_DELAY) {
                            break;
                        }
                    }
                }
            }
        }
        logger.error("连接服务器失败，服务器地址：{}:{} ,重试{}次后仍失败", host, port, retryCount);
        return null;
    }


    /**
     * 对外暴露的发送消息方法
     *
     * @param requestMessage 请求消息
     * @return 响应消息
     */
    public ResponseMessage send(RequestMessage requestMessage) {
        byte[] send = send(requestMessage.encode());
        return new ResponseMessage(send);
    }

}

