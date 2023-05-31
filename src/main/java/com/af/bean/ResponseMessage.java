package com.af.bean;

import cn.hutool.core.util.HexUtil;
import com.af.utils.BytesBuffer;
import com.af.utils.SM4Utils;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/19 18:09
 */
@Getter
public class ResponseMessage {
    /**
     * 日志
     */
    private static final Logger logger = LoggerFactory.getLogger(ResponseMessage.class);

    /**
     * 响应头 参与通信编码
     */
    private final ResponseHeader header;

    /**
     * 数据  参与通信编码
     */
    private final byte[] data;

    /**
     * 响应是否加密
     */
    private boolean isEncrypt;

    /**
     * 响应时间
     */
    @Setter
    private long time;

    public ResponseMessage(byte[] data) {
        //判空
        if (data == null || data.length < ResponseHeader.HEADER_LENGTH) {
            logger.error("响应数据为空或长度小于响应头长度");
            throw new IllegalArgumentException("响应数据为空或长度小于响应头长度");
        }
        this.header = new ResponseHeader(data);
        this.data = subBytes(data, ResponseHeader.HEADER_LENGTH, data.length);
    }


    public ResponseMessage(byte[] data, boolean isEncrypt) {
        this.isEncrypt = isEncrypt;
        //判空
        if (data == null || data.length < ResponseHeader.HEADER_LENGTH) {
            logger.error("响应数据为空或长度小于响应头长度");
            throw new IllegalArgumentException("响应数据为空或长度小于响应头长度");
        }
        this.header = new ResponseHeader(data);
        byte[] data1 = subBytes(data, ResponseHeader.HEADER_LENGTH, data.length);
        this.data = isEncrypt ? SM4Utils.decrypt(data1, SM4Utils.ROOT_KEY) : data1;
    }

    /**
     * 截取字节数组
     *
     * @param src   源数组
     * @param start 开始位置
     * @param end   结束位置
     */
    public static byte[] subBytes(byte[] src, int start, int end) {
        byte[] bs = new byte[end - start];
        System.arraycopy(src, start, bs, 0, end - start);
        return bs;
    }


    /**
     * 获取数据缓冲区
     */
    public BytesBuffer getDataBuffer() {
        return new BytesBuffer(data);
    }


    //toString
    public String toString() {
        return "ResponseMessage(header=" + this.getHeader()
                + ", data=" + HexUtil.encodeHexStr(null == this.getData() ? new byte[0] : this.getData())
                + ", time=" + this.getTime()
                + ", isEncrypt=" + this.isEncrypt() + ")";
    }
}
