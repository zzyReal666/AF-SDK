package com.af.bean;

import cn.hutool.core.util.HexUtil;
import com.af.utils.BytesBuffer;
import com.af.utils.SM4Utils;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 请求消息体 请求头+数据
 * @since 2023/4/18 17:48
 */
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
     * 是否加密
     */
    private boolean isEncrypt = true;

    /**
     * agKey
     */
    private byte[] agKey = new byte[0];

    /**
     * 请求消息体 构建
     *
     * @param cmd  命令码
     * @param data 数据
     */
    public RequestMessage(int cmd, byte[] data, byte[] agKey) {
        if (null == agKey) {
            this.isEncrypt = false;
        } else {
            this.agKey = agKey;
        }

        if (data == null || data.length == 0) {
            this.header = new RequestHeader(0, cmd);
            this.data = null;
        } else {
            this.data = null == agKey ? data : SM4Utils.encrypt(data, agKey);  // 加密 如果agKey为null 则不加密
            this.header = new RequestHeader(this.data.length, cmd);
        }
    }

    public RequestMessage(int cmd) {
        this(cmd, null, null);
    }

    /**
     * 请求是否加密 默认加密
     */
    public RequestMessage setIsEncrypt(boolean isEncrypt) {
        this.isEncrypt = isEncrypt;
        return this;
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
        String data;


        String result = "RequestMessage(header=" + this.getHeader()
                + ", isEncrypt=" + this.isEncrypt();

        if (null == this.data || this.data.length == 0) {  // 无数据
            data = "";
            result += ", data=" + data;
        } else if (this.data.length > 128) {               // 数据过长只显示长度
            data = Integer.toString(this.data.length);
            result += ", dataLen=" + data;
        } else {                                           // 数据正常
            data = HexUtil.encodeHexStr(this.data);
            result += ", data=" + data;
        }
        result += ")";
        return result;
    }

    public void setTaskNo(int taskNo) {
        this.header.setTaskNO(taskNo);
    }
}
