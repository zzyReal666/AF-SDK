package com.af.nettyNew;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.SpecialRequestsType;
import com.af.netty.NettyClient;
import com.af.utils.BytesBuffer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.pool.FixedChannelPool;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 多通道连接池 客户端
 * @since 2023/6/19 11:08
 */
@Getter
@Setter
public class NettyClientChannels implements NettyClient {
    private static final Logger logger = LoggerFactory.getLogger(NettyClientChannels.class);

    final NettyChannelPool nettyChannelPool = new NettyChannelPool(NettyClientChannels.this);

    private int taskNo;
    FixedChannelPool channelPool;

    //region//建造者模式
    private NettyClientChannels(String host, int port, String password, int taskNo) {
        nettyChannelPool.setHost(host);
        nettyChannelPool.setPort(port);
        nettyChannelPool.setPassword(password);
        this.taskNo = taskNo;
        //连接
        connect();
        //登录
        login();
    }


    /**
     * 建造者模式
     */
    public static class Builder {
        public final NettyClientChannels instance;

        public Builder(String host, int port, String password, int taskNo) {
            instance = new NettyClientChannels(host, port, password, taskNo);
        }

        public Builder timeout(int timeout) {
            instance.nettyChannelPool.setTimeout(timeout);
            return this;
        }

        public Builder responseTimeout(int responseTimeout) {
            instance.nettyChannelPool.setResponseTimeout(responseTimeout);
            return this;
        }

        public Builder retryCount(int retryCount) {
            instance.nettyChannelPool.setRetryCount(retryCount);
            return this;
        }

        public Builder retryInterval(int retryInterval) {
            instance.nettyChannelPool.setRetryInterval(retryInterval);
            return this;
        }

        public Builder bufferSize(int bufferSize) {
            instance.nettyChannelPool.setBufferSize(bufferSize);
            return this;
        }

        public Builder channelCount(int channelCount) {
            instance.nettyChannelPool.setChannelCount(channelCount);
            return this;
        }

        public NettyClientChannels build() {
            return instance;
        }

    }
    //endregion

    /**
     * 回调函数
     */
    public static class CallbackService {
        public volatile byte[] result;

        public void receiveMessage(byte[] receive) throws Exception {
            synchronized (this) {
                result = receive;
                this.notify();
            }
        }
    }

    /**
     * 发送消息并且接收响应
     */
    public ResponseMessage send(RequestMessage requestMessage) {

        requestMessage.setTaskNo(taskNo);
        logger.info(requestMessage.isEncrypt() ? "加密==>{}" : "==>{}", requestMessage);
        //开始时间
        long startTime = System.currentTimeMillis();
        //编码
        byte[] req = requestMessage.encode();
        //发送数据
        byte[] res = send(req, requestMessage.getHeader().getTaskNO());
        ResponseMessage responseMessage = new ResponseMessage(res, requestMessage.isEncrypt(), requestMessage.getAgKey());
        //结束时间
        long endTime = System.currentTimeMillis();
        responseMessage.setTime(endTime - startTime);
        logger.info(responseMessage.isEncrypt() ? "加密<=={}" : "<=={}", responseMessage);
        return responseMessage;
    }


    /**
     * 发送数据 接收响应 需要同一通道计算情况下使用
     *
     * @param requestMessage 请求报文
     * @param type           请求类型
     */
    public ResponseMessage send(RequestMessage requestMessage, SpecialRequestsType type) {
        logger.info(requestMessage.isEncrypt() ? "加密==>{}" : "==>{}", requestMessage);
        //开始时间
        long startTime = System.currentTimeMillis();
        //编码
        byte[] req = requestMessage.encode();
        //发送数据
        byte[] res = send(req, requestMessage.getHeader().getTaskNO(), type);
        ResponseMessage responseMessage = new ResponseMessage(res, requestMessage.isEncrypt(), requestMessage.getAgKey());
        //结束时间
        long endTime = System.currentTimeMillis();
        responseMessage.setTime(endTime - startTime);
        logger.info(responseMessage.isEncrypt() ? "加密<=={}" : "<=={}", responseMessage);
        return responseMessage;
    }


    public byte[] send(byte[] msg, int seq) {
        //获取通道
        Channel channel;
        try {
            channel = nettyChannelPool.syncGetChannel();
        } catch (InterruptedException e) {
            logger.error("获取通道失败");
            throw new RuntimeException(e);
        }
        //创建回调函数
        return sendAndReceive(msg, seq, channel);
    }

    public byte[] send(byte[] msg, int seq, SpecialRequestsType type) {
        //获取通道
        Channel channel;
        if (type.equals(SpecialRequestsType.SessionKey)) {
            channel = nettyChannelPool.getChannels().get(0);
        } else if (type.equals(SpecialRequestsType.Hash)) {
            channel = nettyChannelPool.getChannels().get(1);
        } else if (type.equals(SpecialRequestsType.NegotiationData)) {
            channel = nettyChannelPool.getChannels().get(2);
        } else if (type == SpecialRequestsType.MAC) {
            channel = nettyChannelPool.getChannels().get(3);
        } else {
            logger.error("type错误");
            throw new RuntimeException("type错误");
        }
        return sendAndReceive(msg, seq, channel);
    }

    private byte[] sendAndReceive(byte[] msg, int seq, Channel channel) {
//        CallbackService callbackService = new CallbackService();
//        ChannelUtils.putCallback2DataMap(channel, seq, callbackService);
//        //发送数据 接收响应
//        try {
//            synchronized (callbackService) {
//                //msg 转为 ByteBuf
//                ByteBuf byteBuf = Unpooled.wrappedBuffer(msg);
//                //发送数据
//                channel.writeAndFlush(byteBuf);
//                //接收数据
//                callbackService.wait(nettyChannelPool.getResponseTimeout());
//            }
//            byte[] result = callbackService.result;
//            //放回通道
//            nettyChannelPool.putChannel(channel);
//            return result;
//        } catch (InterruptedException e) {
//            logger.error("发送数据失败");
//            throw new RuntimeException(e);
//        }

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
            //放回通道
            nettyChannelPool.putChannel(channel);
            return read;
        } catch (InterruptedException e) {
            logger.error("发送数据失败");
            throw new RuntimeException(e);
        }


    }
    private byte[] read() throws InterruptedException {
        //阻塞当前线程 等待数据返回 指定超时时间
        this.wait(nettyChannelPool.getTimeout());
        byte[] data = NettyHandler.response;
        NettyHandler.response = null;
        return data;
    }


    /**
     * 连接到服务器 创建通道
     */
    private void connect() {
        nettyChannelPool.init();
    }


    /**
     * 登录
     */
    private void login() {
        byte[] psw = nettyChannelPool.getPassword().getBytes();
        byte[] param = new BytesBuffer().append(psw).toBytes();
        ResponseMessage responseMessage = null;
        for (int i = 0; i < nettyChannelPool.getChannelCount(); i++) {
            responseMessage = send(new RequestMessage(0x00000000, param, null));
        }
        if (null == responseMessage || responseMessage.getHeader().getErrorCode() != 0x00000000) {
            logger.error("登录失败");
            throw new RuntimeException("登录失败");
        }
        logger.info("服务端版本号{}", new String(responseMessage.getDataBuffer().readOneData()));
        logger.info("客户端版本号{}", new String("1.0.0".getBytes()));
    }

    /**
     * 关闭连接 关闭全部通道
     */
    public void close() {
        nettyChannelPool.close();
    }

}
