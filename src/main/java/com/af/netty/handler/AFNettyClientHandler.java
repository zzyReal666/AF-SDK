package com.af.netty.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import lombok.Getter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/20 15:47
 */
@Getter
public class AFNettyClientHandler extends ChannelInboundHandlerAdapter {

    private byte[] request;

    /**
     * 读取服务端返回的消息
     *
     * @param ctx 上下文
     * @param msg 消息-字节数组,需要自行解码封装为对象
     * @throws Exception 异常
     */
    @Override
    public void channelRead(io.netty.channel.ChannelHandlerContext ctx, Object msg) throws Exception {

    }








    /**
     * 关闭通道 释放资源
     *
     * @param ctx   上下文
     * @param cause 异常
     * @throws Exception 异常
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        ctx.close();
    }


}
