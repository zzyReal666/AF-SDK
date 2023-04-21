package com.af.bean;

import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.symmetric.SM4;
import com.af.constant.CmdConsts;
import com.af.utils.BytesBuffer;
import lombok.Getter;
import lombok.ToString;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 17:48
 */
@ToString
@Getter
public class RequestMessage {
    /**
     * 用于生成请求ID
     */
    private static final AtomicInteger atomicInteger = new AtomicInteger(1);
    /**
     * 包长度
     */
    private int length;
    /**
     * 请求ID
     */
    private final int requestId;
    /**
     * 命令码
     */
    private final int cmd;
    /**
     * 数据
     */
    private final byte[] data;
    /**
     * 协商密钥
     */
    private final byte[] agreementKey;
    /**
     * 密文数据
     */
    private byte[] cipherData;
    /**
     * 请求头长度常量
     */
    public static final int HEADER_LENGTH = 12;

    /**
     * 请求消息体 构建
     *
     * @param cmd  命令码
     * @param data 数据
     */
    public RequestMessage(int cmd, byte[] data) {
        this(cmd, data, null);
    }

    /**
     * 请求消息体 构建
     *
     * @param cmd          命令码
     * @param data         数据
     * @param agreementKey 协商密钥，为空代表明文通信
     */
    public RequestMessage(int cmd, byte[] data, byte[] agreementKey) {
        this.cmd = cmd;
        this.data = data;
        this.agreementKey = agreementKey;
        length = HEADER_LENGTH + data.length;
        if (CmdConsts.CMD_LOGIN == cmd) {
            requestId = 0;
        } else {
            requestId = atomicInteger.incrementAndGet();
        }
        if (agreementKey != null) {
            SM4 sm4Padding = new SM4(Mode.ECB, Padding.PKCS5Padding, agreementKey);
            cipherData = sm4Padding.encrypt(data);
            length = HEADER_LENGTH + cipherData.length;
        }
    }


    /**
     * 转换为字节数组
     *
     * @return  字节数组
     */
    public byte[] toBytes() {
        BytesBuffer buf = new BytesBuffer();
        buf.append(length);
        buf.append(requestId);
        buf.append(cmd);
        // 如果密文数据不为空，使用密文数据，否则使用明文数据
        buf.append(cipherData == null ? data : cipherData);
        return buf.toBytes();
    }

    /**
     * 是否密文通信
     */
    public boolean isEncrypt() {
        // 密文数据不为空，代表密文通信
        return cipherData != null;
    }

}
