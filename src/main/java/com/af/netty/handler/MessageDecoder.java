package com.af.netty.handler;

import cn.hutool.core.util.ByteUtil;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;

import java.util.List;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description   解码器 从输入流中解析出对象 用于解析服务端返回的数据 暂时未使用到
 * @since 2023/4/20 11:49
 */
public class MessageDecoder extends ByteToMessageDecoder {
    /**
     * Decode the from one {@link ByteBuf} to an other. This method will be called till either the input
     * {@link ByteBuf} has nothing to read when return from this method or till nothing was read from the input
     * {@link ByteBuf}.
     *
     * @param ctx the {@link ChannelHandlerContext} which this {@link ByteToMessageDecoder} belongs to
     * @param in  the {@link ByteBuf} from which to read data
     * @param out the {@link List} to which decoded messages should be added
     * @throws Exception is thrown if an error occurs
     */
    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        if (in.readableBytes() < 12) {
            // 长度短了，数据包不完整，需要等待后面的包来
            // return 就是等待后面的包，out.add就是向下传递。
            return;
        }
        in.markReaderIndex(); // 标记当前读指针的位置
        byte[] lcBytes = new byte[4];
        in.readBytes(lcBytes);
        int lc = ByteUtil.bytesToInt(lcBytes);
        if (in.readableBytes() < lc - 4) {
            // 报文还没收全
            in.resetReaderIndex(); // 指针返回标记位置
            return; // return 就是等待
        }
        in.resetReaderIndex();
        byte[] data = new byte[lc];
        in.readBytes(data);
        out.add(data); // add 之后就会调用channelRead
    }
}
