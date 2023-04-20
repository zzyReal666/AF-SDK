package com.af.bean;

import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.symmetric.SM4;
import com.af.utils.BytesBuffer;
import lombok.Getter;
import lombok.ToString;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/19 18:09
 */
@ToString
@Getter
public class ResponseMessage {

    private final int length; // 包长度
    private final int requestId; // 请求ID
    private final int status; // 结果状态码 0x00000000:成功
    private final byte[] data; // 数据
    private final long costMillis; // 响应时间
    private BytesBuffer dataBuffer;


    /**
     * 服务端响应消息体
     * @param request 请求消息体
     * @param data 数据
     * @param costMillis 响应时间
     */
    public ResponseMessage(RequestMessage request, byte[] data, long costMillis) {
        BytesBuffer buf = new BytesBuffer(data);
        this.length = buf.readInt();
        this.requestId = buf.readInt();
        this.status = buf.readInt();
        this.costMillis = costMillis;
        if (request.isEncrypt()) {
            SM4 sm4NoPadding = new SM4(Mode.ECB, Padding.NoPadding, request.getAgreementKey());
            this.data = sm4NoPadding.decrypt(buf.toBytes());
        } else {
            this.data = buf.toBytes();
        }
        this.dataBuffer = new BytesBuffer(this.data);
    }

}
