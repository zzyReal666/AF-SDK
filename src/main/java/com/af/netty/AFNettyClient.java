package com.af.netty;

import com.af.netty.handler.AFNettyClientHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/20 10:45
 */


public class AFNettyClient {
    //日志
    private static final Logger logger = LoggerFactory.getLogger(AFNettyClient.class);

    //重试参数
    private static final int MAX_RETRY = 10; // 最大重试次数
    private static final int RETRY_DELAY = 5; // 重试间隔时间（秒）
    private int retryCount = 0; // 当前重试次数

    //单例
    private static volatile AFNettyClient instance;

    //netty
    private final Bootstrap bootstrap;
    private final String host;
    private final int port;
    private final EventLoopGroup group;
    private Channel channel;

    /**
     * 私有构造器
     *
     * @param host 服务器地址
     * @param port 服务器端口
     */
    private AFNettyClient(String host, int port) {
        this.host = host;
        this.port = port;
        this.group = new NioEventLoopGroup();
        this.bootstrap = new Bootstrap()
                .group(group)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.TCP_NODELAY, true)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    public void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new AFNettyClientHandler());
                    }
                });
        //获取连接
        connect();
    }

    /**
     * 获取单例
     *
     * @param host 服务器地址
     * @param port 服务器端口
     * @return 单例 AFNettyClient
     */
    public static AFNettyClient getInstance(String host, int port) {
        if (instance == null) {
            synchronized (AFNettyClient.class) {
                if (instance == null) {
                    instance = new AFNettyClient(host, port);
                }
            }
        }
        return instance;
    }

    /**
     * 连接服务器 重连机制
     */
    private void connect() {
        if (channel != null && channel.isActive()) {
            logger.info("连接成功");
            retryCount = 0;
            return;
        }
        retryCount++;
        if (retryCount > MAX_RETRY) {
            logger.error("重试次数已用完，放弃连接");
            return;
        }
        logger.info("开始连接服务器，第{}次连接", retryCount);
        ChannelFuture future = bootstrap.connect(host, port);
        future.addListener(new ChannelFutureListener() {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception {
                if (future.isSuccess()) {
                    logger.info("连接服务器成功");
                    channel = future.channel();
                } else {
                    logger.info("第{}次连接服务器失败,{}秒后重试", retryCount, RETRY_DELAY);
                    future.channel().eventLoop().schedule(new Runnable() {
                        @Override
                        public void run() {
                            connect();
                        }
                    }, RETRY_DELAY, java.util.concurrent.TimeUnit.SECONDS);
                }
            }
        });
    }

    /**
     * 发送消息
     *
     */
    public void sendMessage(byte[] message) throws InterruptedException {
        int maxRetryTimes = 3; // 最大重试次数
        int retryInterval = 1000; // 重试间隔时间，单位为毫秒
        int retryTimes = 0; // 当前重试次数
        while (true) {
            retryTimes++;
            if (channel == null || !channel.isActive()) {
                // 如果通道不存在或已经不活跃，重新获取通道连接
                connect();
            }
            try {
                ByteBuf buf = Unpooled.copiedBuffer(message);
                ChannelFuture future = channel.writeAndFlush(buf);
                future.sync(); // 等待发送结果返回
                if (future.isSuccess()) {
                    // 发送成功，退出循环
                    break;
                }
            } catch (InterruptedException e) {
                // 发送过程中出现异常，记录日志并减少重试次数
                logger.error("第{}次发送数据失败,等待重试",retryTimes,e);
                if (retryTimes >= maxRetryTimes) {
                    // 超过最大重试次数，退出循环
                    break;
                }
            } finally {
                if (retryTimes > 0) {
                    // 休眠一段时间后重试
                    Thread.sleep(retryInterval);
                }
            }
        }
    }


    /**
     * 关闭连接 释放资源
     */
    public void shutdown() {
        if (channel != null) {
            channel.close();
        }
        group.shutdownGracefully();
    }
}
