package com.af.bean;

import cn.hutool.core.util.HexUtil;
import com.af.constant.CMDCode;
import com.af.crypto.algorithm.sm4.SM4;
import com.af.device.impl.AFTSDevice;
import com.af.utils.BytesBuffer;
import com.af.utils.SM4Utils;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

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
     * 请求消息体 构建
     *
     * @param cmd  命令码
     * @param data 数据
     */
    public RequestMessage(int cmd, byte[] data, byte[] agKey) {
        if (null == agKey) {
            this.isEncrypt = false;
        }
        if (data == null || data.length == 0) {
            this.header = new RequestHeader(0, cmd);
            this.data = null;
        } else {
            this.header = new RequestHeader(data.length, cmd);
            this.data = null == agKey ? data : SM4Utils.encrypt(data, agKey);
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
        return "RequestMessage(header=" + this.getHeader()
                + ", data=" + HexUtil.encodeHexStr(null == this.getData() ? "".getBytes() : this.getData())
                + ", isEncrypt=" + this.isEncrypt() + ")";
    }
}
