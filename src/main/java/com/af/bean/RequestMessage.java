package com.af.bean;

import lombok.Getter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 请求消息体 请求头+数据
 * @since 2023/4/18 17:48
 */
@ToString
@Getter
public class RequestMessage {

    private static final Logger logger = LoggerFactory.getLogger(RequestMessage.class);
    /**
     * 请求头
     */
    private final RequestHeader header;
    /**
     * 数据
     */
    private final byte[] data;


    /**
     * 请求消息体 构建
     *
     * @param cmd  命令码
     * @param data 数据
     */
    public RequestMessage(int cmd, byte[] data) {
        if (data == null) {
            data = new byte[0];
            logger.warn("请求数据为空,只包含请求头");
        }
        this.header = new RequestHeader(data.length, cmd);
        if (cmd == 0x00000000) {
            this.data = data;   //登录请求不加密
        } else {
//            this.data = SM4Utils.encrypt(data, SM4Utils.ROOT_KEY);
            this.data = data;
        }

    }

    public RequestMessage(int cmd) {
        this(cmd, null);
    }

    /**
     * 转换为字节数组
     *
     * @return 字节数组
     */
    public byte[] encode() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(this.header.encode());
            out.write(this.data);
        } catch (IOException e) {
            logger.error("请求转换为字节数组失败", e);
        }
        return out.toByteArray();
    }
}
