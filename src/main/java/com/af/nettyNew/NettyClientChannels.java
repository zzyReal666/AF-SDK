package com.af.nettyNew;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.constant.SpecialRequestsType;
import com.af.netty.NettyClient;
import com.af.utils.BytesBuffer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 多通道连接池 客户端
 * @since 2023/6/19 11:08
 */
@Getter
@Setter
@ToString
public class NettyClientChannels implements NettyClient {

    private static final Logger logger = LoggerFactory.getLogger(NettyClientChannels.class);

    public NettyChannelPool nettyChannelPool;

    private int taskNo;

    private byte[] heartBeat;

    //私有无参构造
    private NettyClientChannels() {
    }



    private static class SingletonHolder {
        private static final NettyClientChannels INSTANCE = new NettyClientChannels();
    }
    //region//建造者模式
    /**
     * 建造者模式
     */
    public static class Builder {
        public final NettyClientChannels instance = new NettyClientChannels();

        public Builder(String host, int port, String password, int taskNo) {
            instance.nettyChannelPool = new NettyChannelPool();
            instance.nettyChannelPool.setHost(host);
            instance.nettyChannelPool.setPort(port);
            instance.nettyChannelPool.setPassword(password);
            instance.taskNo = taskNo;
            byte[] param = new BytesBuffer().append(0).toBytes();
            RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_HEARTBEAT, param, null);
            instance.heartBeat = requestMessage.encode();
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
            instance.connect();
            instance.login();
            instance.nettyChannelPool.setClientChannels(instance);
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


    /**
     * 发送数据 接收响应
     *
     * @param msg     消息
     * @param seq     序列号
     * @param channel 通道
     * @return 响应
     */
    private byte[] sendAndReceive(byte[] msg, int seq, Channel channel) {
        CallbackService callbackService = new CallbackService();
        ChannelUtils.putCallback2DataMap(channel, seq, callbackService);
        //发送数据 接收响应
        try {
            synchronized (callbackService) {
                //msg 转为 ByteBuf
                ByteBuf byteBuf = Unpooled.wrappedBuffer(msg);
                //发送数据
                channel.writeAndFlush(byteBuf);
                //接收数据
                callbackService.wait(nettyChannelPool.getResponseTimeout());
            }
            return callbackService.result;
        } catch (InterruptedException e) {
            logger.error("发送数据失败");
            throw new RuntimeException(e);
        } finally {
            //放回通道
            nettyChannelPool.putChannel(channel);
        }
    }


    /**
     * 连接到服务器 创建通道
     */
    void connect() {
        nettyChannelPool.init();
    }

    /**
     * 登录
     */
    public void login() {
        byte[] psw = nettyChannelPool.getPassword().getBytes();
        byte[] param = new BytesBuffer().append(psw).toBytes();
        ResponseMessage responseMessage = null;
        responseMessage = send(new RequestMessage(0x00000000, param, null));
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

    //空实现
    @Override
    public ResponseMessage send(RequestMessage requestMessage, SpecialRequestsType type) {
        return null;
    }

}
