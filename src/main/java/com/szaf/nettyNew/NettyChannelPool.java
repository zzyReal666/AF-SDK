package com.szaf.nettyNew;

import com.szaf.constant.SpecialRequestsType;
import com.szaf.netty.handler.MyDecoder;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.Attribute;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

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
     * 是否启用状态 默认启用  主动关闭后不再启用 netty异常处理不在启用
     */
    private boolean isAvailable = true;

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


//    /**
//     * channels  用于需要同一个通道计算的情况
//     */
//    private Map<ChannelId, Channel> channels = new ConcurrentHashMap<>();

    /**
     * channel 用于需要同一个通道计算的情况
     */
    private List<Channel> channels = new CopyOnWriteArrayList<>();


    //endregion

    public NettyChannelPool(int channelCount) {
        this.channelCount = channelCount;
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
     * 同步获取netty channel
     * 从队列中获取
     */
    public Channel syncGetChannel() throws InterruptedException {
        Channel channel = channelQueue.poll();
        //如果通道池中没有通道 则等待
        if (channel == null) {
            synchronized (this) {
                this.wait();
            }
            channel = channelQueue.poll();
        }
        return channel;
    }

    /**
     * 连接到服务端  此方法只能获取到一个channel
     *
     * @return channel
     */
    private synchronized Channel connectToServer() throws InterruptedException {

        if (retryCount <= 0) {
            throw new RuntimeException("重试3次失败，连接服务端失败");
        }
        //连接服务端 添加监听器 重试机制
        ChannelFuture channelFuture = bootstrap.connect(host, port).addListener((ChannelFutureListener) future -> {
            if (!future.isSuccess()) {
                logger.error("连接服务端失败，正在重试,剩余重试次数:{}", retryCount--);
                future.channel().eventLoop().schedule(this::connectToServer, timeout, TimeUnit.MILLISECONDS);
            }
        });
        Channel channel = channelFuture.sync().channel();
        //为刚刚创建的channel，初始化channel属性
        Attribute<Map<Integer, Object>> attribute = channel.attr(ChannelUtils.DATA_MAP_ATTRIBUTEKEY);
        ConcurrentHashMap<Integer, Object> dataMap = new ConcurrentHashMap<>();
        attribute.set(dataMap);
        return channel;
    }

    /**
     * 初始化 通道池获取通道
     */
    public void init() {
        setBootStrap();
        initChannels();
    }

//    private void initListChannels() {
//        for (int i = 0; i < channelCount; i++) {
//            try {
//                Channel channel = connectToServer();
//                channels.put(channel.id(), channel);
//                //初始化需要同一个通道计算的情况
//            } catch (InterruptedException e) {
//                logger.error("初始化通道池失败", e);
//            }
//        }
//    }

    /**
     * 初始化通道池
     */
    protected void initChannels() {
        //初始化通道池
        for (int i = 0; i < channelCount; i++) {
            try {
                Channel channel = connectToServer();
                channelQueue.offer(channel);
                //初始化需要同一个通道计算的情况
            } catch (InterruptedException e) {
                logger.error("初始化通道池失败", e);
            }
        }

        try {
            //遍历SpecialRequestsType 枚举
            for (SpecialRequestsType specialRequestsType : SpecialRequestsType.values()) {
                channels.add(connectToServer());
            }
        } catch (InterruptedException e) {
            logger.error("初始化通道池失败", e);
        }

        //队列输出channelId
        channelQueue.forEach(channel -> logger.info("channelId:{}", channel.id()));
    }

    /**
     * 设置bootstrap
     */
    private void setBootStrap() {
        EventLoopGroup eventLoopGroup = new NioEventLoopGroup();
        bootstrap.group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.SO_RCVBUF, bufferSize)
                .option(ChannelOption.TCP_NODELAY, true)  //不写缓存
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 7000)  //连接超时时间
                .option(ChannelOption.SO_KEEPALIVE, true) //保持连接
                .handler(new LoggingHandler(LogLevel.INFO))
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) throws Exception {
                        ChannelPipeline pipeline = ch.pipeline();
                        pipeline.addLast(new MyDecoder());
                        ch.pipeline().addLast(new NettyHandler(NettyChannelPool.this));
                    }
                });
    }

    /**
     * 关闭通道池
     */
    public void close() {
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

    public void putChannel(Channel channel) {
        channelQueue.offer(channel);
        synchronized (this) {
            this.notify();
        }
    }
}
