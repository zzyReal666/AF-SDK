package com.af.netty;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.netty.handler.AFNettyClientHandler;
import com.af.utils.BytesBuffer;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.logging.LoggingHandler;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/20 10:45
 */

@Getter
@ToString
public class AFNettyClient {
    //日志
    private static final Logger logger = LoggerFactory.getLogger(AFNettyClient.class);

    //重试参数
    @Setter
    private int MAX_RETRY = 3; // 最大重试次数
    @Setter
    private int RETRY_DELAY = 5000; // 重试间隔时间（秒）
    private int retryCount = 0; // 当前重试次数

    //连接超时时间
    @Setter
    private int TIMEOUT = 7000; // 超时时间（毫秒）
    //响应超时时间
    @Setter
    private int RESPONSE_TIMEOUT = 10000; // 超时时间（毫秒）


    //单例
    private static volatile AFNettyClient instance;


    //netty
    private final Bootstrap bootstrap;
    private Channel channel;
    private final String host;
    private final int port;
    private final String password;


    /**
     * 私有构造器
     *
     * @param host 服务器地址
     * @param port 服务器端口
     */
    protected AFNettyClient(String host, int port, String password) {
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
     * 连接
     */
    public void connect() {
        if (channel != null && channel.isActive()) {
            return;
        }
        try {
            ChannelFuture future = bootstrap.handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ch.pipeline().addLast(new LoggingHandler());
                    ch.pipeline().addLast(new AFNettyClientHandler(AFNettyClient.this));
                }
            }).connect(host, port).sync();
            channel = future.channel();
        } catch (Exception e) {
            logger.error("连接失败");
            if (retryCount < MAX_RETRY) {
                retryCount++;
                try {
                    Thread.sleep(RETRY_DELAY);
                } catch (InterruptedException interruptedException) {
                    interruptedException.printStackTrace();
                }
                logger.info("第{}次重试", retryCount);
                connect();
            } else {
                logger.error("重试次数超过最大重试次数,请检查网络连接");
                throw new RuntimeException(e);
            }
        }
    }


    /**
     * 发送数据
     */
    public ResponseMessage send(RequestMessage requestMessage) {
        logger.info("==> {}", requestMessage);
        byte[] req = requestMessage.encode();
        byte[] res = send(req);
        logger.info("<== {}", new ResponseMessage(res));
        return new ResponseMessage(res);
    }

    public byte[] send(byte[] msg) {
        if (channel == null || !channel.isActive()) {
            connect();
        }
        try {
            //msg 转为 ByteBuf
            ByteBuf byteBuf = Unpooled.wrappedBuffer(msg);
            byte[] read;
            synchronized (this) {
                //发送数据
                channel.writeAndFlush(byteBuf).sync();
                //接收数据
                read = read();
            }
            return read;
        } catch (InterruptedException e) {
            logger.error("发送数据失败");
            throw new RuntimeException(e);
        }
    }

    private byte[] read() throws InterruptedException {
        //阻塞当前线程 等待数据返回 指定超时时间
        this.wait(TIMEOUT);
        byte[] data = AFNettyClientHandler.response;
        AFNettyClientHandler.response = null;
        return data;
    }


    /**
     * 登录 在获取client实例时自动登录
     */
    private void login() {
        byte[] psw = password.getBytes();
        byte[] param = new BytesBuffer().append(psw).toBytes();
        ResponseMessage responseMessage = send(new RequestMessage(0x00000000, param));
        //todo 客户端版本号
//        logger.info("服务端版本号{}", new String(responseMessage.getDataBuffer().readOneData()));
        if (responseMessage.getHeader().getErrorCode() != 0x00000000) {
            logger.error("登录失败,请检查密码是否正确!");
            throw new RuntimeException("登录失败,密码错误!");
        }
    }


}

