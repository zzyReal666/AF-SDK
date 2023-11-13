package com.af.nettyNew;

import com.af.device.impl.AFHsmDevice;
import com.af.netty.handler.MyDecoder;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.Attribute;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/6/15 17:49
 */
@Getter
@Setter
public class NettyChannelPool {

    //region//======>属性
    private static final Logger logger = LoggerFactory.getLogger(NettyChannelPool.class);

    private NettyClientChannels clientChannels;

    private boolean loginStatus = false;

    /**
     * 主机
     */
    private String host;
    /**
     * 端口
     */
    private int port;

    /**
     * 密码
     */
    private String password;
    /**
     * 连接超时时间
     */
    private int timeout = 5000;

    /**
     * 响应超时时间
     */
    private int responseTimeout = 10000;

    /**
     * 重试次数
     */
    private int retryCount = 3;

    /**
     * 重试间隔时间
     */
    private int retryInterval = 5000;

    /**
     * 缓冲区大小
     */

    private int bufferSize = 1024 * 1024 * 2;

    /**
     * 通道数量
     */
    private int channelCount = 10;

    /**
     * 是否异常关闭状态,默认为true,调用close()方法后为false
     */
    private boolean isExceptionStatus = true;

    /**
     * 连接池是否可用 默认为false 初始化后为true 调用close()方法后为false 异常后为false
     */
    private boolean isAvailable = false;

    /**
     * 通道数组
     */
    private final Queue<Channel> channelQueue;

    /**
     * 锁数组
     */
    private final Object[] locks;

    /**
     * bootstrap
     */
    private Bootstrap bootstrap = new Bootstrap();

    //endregion


    public NettyChannelPool(NettyClientChannels clientChannels) {
        this.channelQueue = new ConcurrentLinkedQueue<>();
        this.locks = new Object[channelCount];
        for (int i = 0; i < channelCount; i++) {
            this.locks[i] = new Object();
        }

    }

    public NettyChannelPool() {
        this.channelQueue = new ConcurrentLinkedQueue<>();
        this.locks = new Object[channelCount];
        for (int i = 0; i < channelCount; i++) {
            this.locks[i] = new Object();
        }
    }


    /**
     * 获取通道
     */
    public Channel syncGetChannel() throws InterruptedException {
        //队首拿出一个通道
        Channel channel = channelQueue.poll();
        //如果队列为空，等待
        while (channel == null) {
            synchronized (this) {
                // 再次判断，防止在等待期间有其他线程放回通道
                channel = channelQueue.poll();
                if (channel == null) {
                    this.wait();
                }
            }
        }
        return channel;
    }

    /**
     * 放回通道
     */
    public void putChannel(Channel channel) {
        if (channel != null) {
            channelQueue.offer(channel);
            synchronized (this) {
                this.notify();
            }
        }
    }

    /**
     * 连接到服务端  此方法只能获取到一个channel  自动重试3次
     *
     * @return channel
     */
    public Channel connectToServer() throws InterruptedException {
        //获取对象锁 从lock[]中获取锁
        int index = (int) (Thread.currentThread().getId() % channelCount);
        synchronized (locks[index]) {
            AtomicInteger retryCount = new AtomicInteger(this.retryCount);
            return connectToServer0(retryCount);
        }
    }

    private Channel connectToServer0(AtomicInteger retryCount) throws InterruptedException {
        if (retryCount.get() <= 0) {
            throw new RuntimeException("重试3次失败，连接服务端失败");
        }
        //连接服务端 添加监听器 重试机制
        ChannelFuture channelFuture = bootstrap.connect(host, port).addListener((ChannelFutureListener) future -> {
            if (!future.isSuccess()) {
                //重试次数减一
                retryCount.decrementAndGet();
                logger.error("连接服务端失败，正在重试...,剩余重试次数:{}", retryCount);
            }
        });
        Channel channel = null;
        try {
            channel = channelFuture.sync().channel();  //阻塞等待连接成功
            Attribute<Map<Channel, Object>> attribute = channel.attr(ChannelUtils.DATA_MAP_ATTRIBUTEKEY);
            ConcurrentHashMap<Channel, Object> dataMap = new ConcurrentHashMap<>();
            attribute.set(dataMap);
        } catch (Exception e) {
            Thread.sleep(retryInterval);
            channel = connectToServer0(retryCount);

        }
        return channel;

    }


    /**
     * 初始化 通道池获取通道
     */
    public void init() {
        setBootStrap();
        initChannels();
        isAvailable = true;
    }

    /**
     * 设置bootstrap
     */
    private void setBootStrap() {
        EventLoopGroup eventLoopGroup = new NioEventLoopGroup();
        bootstrap.group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.SO_RCVBUF, bufferSize).
                option(ChannelOption.TCP_NODELAY, true)  //不写缓存
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, timeout)  //连接超时时间
                .option(ChannelOption.SO_KEEPALIVE, true) //保持连接
                .handler(new LoggingHandler(LogLevel.INFO)).handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) throws Exception {
                        ChannelPipeline pipeline = ch.pipeline();
                        pipeline.addLast(new MyDecoder());
                        pipeline.addLast(new IdleStateHandler(0, 4, 0, TimeUnit.SECONDS));
                        pipeline.addLast(new NettyHandler(NettyChannelPool.this));
                    }
                });
    }

    /**
     * 初始化通道池
     */
    protected void initChannels() {
        //初始化通道池
        for (int i = 0; i < channelCount; i++) {
            Channel channel = null;
            try {
                channel = connectToServer();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            channelQueue.offer(channel);
        }
        //队列输出channelId
        logger.info("初始化通道池成功,共有通道数量:{}", channelQueue.size());
        channelQueue.forEach(channel -> logger.info("channelId:{},remoteAddress:{},localAddress:{}", channel.id(), channel.remoteAddress(), channel.localAddress()));
    }


    /**
     * 关闭通道池
     */
    public void close() {
        //标志是否异常关闭
        isExceptionStatus = false;
        //标志通道池不可用
        isAvailable = false;
        //关闭通道池
        for (Channel channel : channelQueue) {
            if (channel != null) {
                channel.close();
            }
        }
        //netty 释放资源
        bootstrap.config().group().shutdownGracefully();
    }

    //重连机制
    public void reconnect(Channel channel) {
        //channelQueue 中删除 channel
        channelQueue.remove(channel);
        //attr中删除对应的map
        channel.attr(ChannelUtils.DATA_MAP_ATTRIBUTEKEY).set(null);
        //获取ipAndPort
        String ipAndPort = channel.remoteAddress().toString();
        ipAndPort = ipAndPort.substring(1);
        if (!AFHsmDevice.containsKey(ipAndPort)) {
            return;  //如果设备已经被删除，不再重连
        }
        synchronized (NettyChannelPool.class) {
            if (!AFHsmDevice.containsKey(ipAndPort)) {
                return;  //如果设备已经被删除，不再重连
            }
            //创建新的channel
            Channel channelNew = null;
            try {
                channelNew = connectToServer();  //连接服务端
                channelQueue.offer(channelNew);  //放入队列
                // 重新协商密钥  只执行一次
                AFHsmDevice.getDevice(ipAndPort).setAgKey();
            } catch (Exception e) {
                logger.error("重连失败,清除设备,{}", clientChannels.getAddr());
//                AFHsmDevice.close(clientChannels.getAddr());
                isAvailable = false;
            }
        }
    }
}
