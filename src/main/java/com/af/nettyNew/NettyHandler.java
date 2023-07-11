package com.af.nettyNew;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/6/20 16:38
 */
public class NettyHandler extends ChannelInboundHandlerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(NettyHandler.class);

    private final NettyChannelPool nettyChannelPool;
    public NettyHandler(NettyChannelPool nettyChannelPool) {
        this.nettyChannelPool = nettyChannelPool;
    }
    public static byte[] response;

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
//        logger.info("与服务器建立连接,连接地址:{},通道ID:{}", ctx.channel().remoteAddress(), ctx.channel().id());
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        byte[] receive = (byte[]) msg;
//        int seq = BytesOperate.bytes2int(receive, 4);
//        NettyClientChannels.CallbackService callbackService = ChannelUtils.<NettyClientChannels.CallbackService>removeCallback( ctx.channel(), seq);
//        callbackService.receiveMessage(receive);
        response = (byte[]) msg;
        //通知客户端，响应已经接收完毕
        synchronized (nettyChannelPool.getClientChannels()) {
            nettyChannelPool.getClientChannels().notifyAll();
        }
    }

    /**
     * 断线重连
     */
    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        logger.info("与服务器断开连接,连接地址:{},通道ID:{}", ctx.channel().remoteAddress(), ctx.channel().id());
        if (nettyChannelPool.isAvailable()) {
            logger.info("开始重连服务器");
            nettyChannelPool.initChannels();
        }
    }
}
