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
 * @since 2023/6/5 10:54
 */
@Getter
public class ResponseMessageForNoEncrypt {
    /**
     * 日志
     */
    private static final Logger logger = LoggerFactory.getLogger(ResponseMessageForNoEncrypt.class);

    /**
     * 响应头 参与通信编码
     */
    private final ResponseHeader header;

    /**
     * 数据  参与通信编码
     */
    private final byte[] data;




    /**
     * 响应时间
     */
    @Setter
    private long time;

    public ResponseMessageForNoEncrypt(byte[] data) {
        //判空
        if (data == null || data.length < ResponseHeader.HEADER_LENGTH) {
            logger.error("响应数据为空或长度小于响应头长度");
            throw new IllegalArgumentException("响应数据为空或长度小于响应头长度");
        }
        this.header = new ResponseHeader(data);
        this.data = subBytes(data, ResponseHeader.HEADER_LENGTH, data.length);
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
                + ")";
    }
}
