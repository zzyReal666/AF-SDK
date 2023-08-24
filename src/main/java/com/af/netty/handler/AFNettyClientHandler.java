package com.af.netty.handler;

import com.af.netty.AFNettyClient;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/20 15:47
 */
@Getter
@Setter
@ChannelHandler.Sharable
public class AFNettyClientHandler extends ChannelInboundHandlerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(AFNettyClientHandler.class);

    private final AFNettyClient nettyClient;
    public static byte[] response;

    public AFNettyClientHandler(AFNettyClient nettyClient) {
        this.nettyClient = nettyClient;
    }


    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        logger.info("与服务器建立连接,连接地址:" + ctx.channel().remoteAddress());
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        logger.debug("入站<=" + msg);
        response = (byte[]) msg;
        //通知客户端，响应已经接收完毕
        synchronized (nettyClient) {
            nettyClient.notifyAll();
        }
    }


}
