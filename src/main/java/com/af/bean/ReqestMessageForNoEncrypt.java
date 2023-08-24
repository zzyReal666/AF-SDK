package com.af.bean;

import cn.hutool.core.util.HexUtil;
import com.af.utils.BytesBuffer;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description    不加密请求
 * @since 2023/6/5 10:54
 */
@Getter
public class ReqestMessageForNoEncrypt {

    private static final Logger logger = LoggerFactory.getLogger(ReqestMessageForNoEncrypt.class);
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
    public ReqestMessageForNoEncrypt(int cmd, byte[] data) {

        if (data == null || data.length == 0) {
            this.header = new RequestHeader(0, cmd);
            this.data = null;
        } else {
            this.data = data;
            this.header = new RequestHeader(this.data.length, cmd);
        }
    }

    public ReqestMessageForNoEncrypt(int cmd) {
        this(cmd, null);
    }



    /**
     * 转换为字节数组
     *
     * @return 字节数组
     */
    public byte[] encode() {
        if (data == null) {
            return header.encode();
        }
        return new BytesBuffer()
                .append(header.encode())
                .append(data)
                .toBytes();
    }

    public String toString() {
        return "RequestMessage(header=" + this.getHeader()
                + ", data=" + HexUtil.encodeHexStr(null == this.getData() ? "".getBytes() : this.getData())
                + ")";
    }
}
