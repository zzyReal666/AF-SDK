package com.af.netty;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/6/21 10:57
 */
public interface NettyClient {

    /**
     * 发送数据 接收响应
     * @param requestMessage 请求报文
     * @return 响应报文
     */
    ResponseMessage send(RequestMessage requestMessage);

    ResponseMessage send(RequestMessage requestMessage, boolean singleChannel);

    /**
     * 关闭连接
     */
    void close();



}
