package com.af.nettyNew;

import com.af.device.impl.AFHsmDevice;
import com.af.utils.BytesOperate;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
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


    /**
     * 心跳
     */
    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        NettyClientChannels.CallbackService callbackService = new NettyClientChannels.CallbackService();
        NettyClientChannels clientChannels = nettyChannelPool.getClientChannels();
        if (clientChannels != null) {
            ChannelUtils.putCallback2DataMap(ctx.channel(), clientChannels.getTaskNo(), callbackService);
            ctx.writeAndFlush(Unpooled.wrappedBuffer(clientChannels.getHeartBeat()));
        }
    }

    /**
     * 断线
     */
    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        logger.info("与服务器断开连接,连接地址:{},通道ID:{}", ctx.channel().remoteAddress(), ctx.channel().id());
        Channel channel = ctx.channel();
        String ipAndPort = channel.remoteAddress().toString();
        ipAndPort = ipAndPort.substring(1);
        System.out.println("ipAndPort:" + ipAndPort);
        if (nettyChannelPool.isAvailable() && AFHsmDevice.containsKey(ipAndPort)) {
//            nettyChannelPool.reconnect(ctx.channel());
            AFHsmDevice.close(ipAndPort);
        }
    }

}
