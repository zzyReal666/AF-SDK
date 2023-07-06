package com.szaf.bean;

import cn.hutool.core.util.StrUtil;
import com.szaf.constant.ErrorNumber;
import com.szaf.utils.BytesOperate;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/21 15:45
 */
@Getter
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


    /**
     * 构造函数
     * @param data  服务端响应的数据,只需要取前12个字节为头
     */
    public ResponseHeader(byte[] data) {
        this.length = BytesOperate.bytes2int(data);
        this.taskNO = BytesOperate.bytes2int(data, 4);
        this.errorCode = BytesOperate.bytes2int(data, 8);
    }


    public String getErrorInfo() {
        return ErrorNumber.toErrorInfo(this.errorCode);
    }



    //toString
    public String toString() {
        return "ResponseHeader(length=" + this.getLength() + ", taskNO=" + this.getTaskNO() + ", errorCode=" + StrUtil.fillBefore(Integer.toHexString(this.getErrorCode()), '0', 8) + ", errorInfo=" + this.getErrorInfo() + ")";
    }
}
