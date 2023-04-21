package com.af.netty.handler;

import com.af.bean.RequestMessage;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

/**
*
* @author zhangzhongyuan@szanfu.cn
* @since  2023/4/20 11:43
* @description
*/
public class MessageEncoder extends MessageToByteEncoder<RequestMessage> {
    /**
     * Encode a message into a {@link ByteBuf}. This method will be called for each written message that can be handled
     * by this encoder.
     *
     * @param ctx the {@link ChannelHandlerContext} which this {@link MessageToByteEncoder} belongs to
     * @param msg the message to encode
     * @param out the {@link ByteBuf} into which the encoded message will be written
     * @throws Exception is thrown if an error occurs
     */
    @Override
    protected void encode(ChannelHandlerContext ctx, RequestMessage msg, ByteBuf out) throws Exception {
        //todo 编码
        out.writeBytes(msg.toBytes());
    }
}
