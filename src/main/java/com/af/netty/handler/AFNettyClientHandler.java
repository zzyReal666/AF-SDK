package com.af.netty.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/20 15:47
 */
@Getter
@NoArgsConstructor
@Setter
@ChannelHandler.Sharable
public class AFNettyClientHandler extends ChannelInboundHandlerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(AFNettyClientHandler.class);

    private byte[] request;
    private ByteBuf response;

    public AFNettyClientHandler(byte[] request) {
        this.request = request;
    }




    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        logger.debug("出站=>" + Arrays.toString(request));
        ByteBuf buf = ctx.alloc().buffer();
        buf.writeBytes(request);
        ctx.writeAndFlush(buf);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        logger.debug("入站=>" + msg);
        response = (ByteBuf) msg;
        ctx.close();
    }

    public byte[] getResponse() {
        byte[] bytes = new byte[response.readableBytes()];
        response.readBytes(bytes);
        return bytes;
    }


}
