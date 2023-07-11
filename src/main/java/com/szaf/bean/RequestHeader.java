package com.szaf.bean;

import com.szaf.constant.CmdConsts;
import com.szaf.utils.BytesBuffer;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 请求头
 * @since 2023/4/19 16:06
 */
@Getter
@Setter
public class RequestHeader {

    /**
     * 日志
     */
    private static final Logger logger = LoggerFactory.getLogger(RequestHeader.class);

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
    protected int taskNO;


    /**
     * CMD 命令码
     */
    protected final int cmd;

    /**
     * 用于生成请求ID
     */
    private static final AtomicInteger atomicInteger = new AtomicInteger(1);


    public RequestHeader(int length, int cmd) {
        this.length = length + HEADER_LENGTH;
        this.cmd = cmd;
        if (CmdConsts.CMD_LOGIN == cmd) {
            taskNO = 0;
        } else {
            taskNO = atomicInteger.incrementAndGet();
        }
    }

    /**
     * 将请求头转换为字节数组  小端模式
     *
     * @return
     */
    public byte[] encode() {
        return new BytesBuffer()
                .append(length)
                .append(taskNO)
                .append(cmd)
                .toBytes();
    }


    //toString
    public String toString() {
        return "RequestHeader(length=" + this.getLength() + ", taskNO=" + this.getTaskNO() + ", cmd=0x" + Integer.toHexString(this.getCmd()) + ")";
    }


}
