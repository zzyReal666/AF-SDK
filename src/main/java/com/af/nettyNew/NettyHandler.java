package com.af.nettyNew;

import com.af.utils.BytesOperate;
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


    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        byte[] receive = (byte[]) msg;
        int seq = BytesOperate.bytes2int(receive, 4);
        NettyClientChannels.CallbackService callbackService = ChannelUtils.<NettyClientChannels.CallbackService>removeCallback(ctx.channel(), seq);
        callbackService.receiveMessage(receive);
    }


//    /**
//     * 心跳
//     */
//    @Override
//    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
//        ctx.writeAndFlush(Unpooled.wrappedBuffer(nettyChannelPool.getClientChannels().getHeartBeat()));
//    }

    /**
     * 断线重连
     */
    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        logger.info("与服务器断开连接,连接地址:{},通道ID:{}", ctx.channel().remoteAddress(), ctx.channel().id());
        if (nettyChannelPool.isAvailable()) {
            nettyChannelPool.reconnect(ctx.channel());
        }
    }
}
