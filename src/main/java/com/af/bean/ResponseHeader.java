package com.af.bean;

import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/21 15:45
 */
@Getter
@ToString
public class ResponseHeader {

    /**
     * 日志
     */
    private static final Logger logger = LoggerFactory.getLogger(ResponseHeader.class);

    /**
     * 请求头长度常量
     */
    public static final int HEADER_LENGTH = 12;

    /**
     * 包长度  头+数据
     */
    protected final int length;


    /**
     * 任务编号
     */
    protected final int taskNO;


    /**
     * 错误码
     */
    protected final int errorCode;


    /**
     * 用于生成请求ID
     */
    private static final AtomicInteger atomicInteger = new AtomicInteger(1);


    public ResponseHeader(byte[] header) {
        this.length = BytesOperate.bytes2int(header);
        this.taskNO = BytesOperate.bytes2int(header, 4);
        this.errorCode = BytesOperate.bytes2int(header, 8);
    }
}
