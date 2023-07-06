package com.szaf.netty;

import com.szaf.bean.RequestMessage;
import com.szaf.bean.ResponseMessage;
import com.szaf.constant.SpecialRequestsType;

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

    ResponseMessage send(RequestMessage requestMessage, SpecialRequestsType type);

    /**
     * 关闭连接
     */
    void close();



}
