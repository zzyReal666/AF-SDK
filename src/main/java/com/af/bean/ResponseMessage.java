package com.af.bean;

import com.af.utils.BytesBuffer;
import lombok.Getter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/19 18:09
 */
@Getter
@ToString
public class ResponseMessage {
    /**
     * 日志
     */
    private static final Logger logger = LoggerFactory.getLogger(ResponseMessage.class);

    /**
     * 响应头
     */
    private final ResponseHeader header;

    /**
     * 数据
     */
    private final byte[] data;

    public ResponseMessage(byte[] data) {
        //判空
        if (data == null || data.length < ResponseHeader.HEADER_LENGTH) {
            logger.error("响应数据为空或长度小于响应头长度");
            throw new IllegalArgumentException("响应数据为空或长度小于响应头长度");
        }
        this.header = new ResponseHeader(data);
        this.data = new byte[data.length - ResponseHeader.HEADER_LENGTH];
        System.arraycopy(data, ResponseHeader.HEADER_LENGTH, this.data, 0, this.data.length);
    }
    //getDataBuffer
    public BytesBuffer getDataBuffer() {
        return new BytesBuffer(data);
    }

}
