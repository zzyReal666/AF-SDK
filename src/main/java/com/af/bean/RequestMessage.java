package com.af.bean;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 17:48
 */
public class RequestMessage {
    /**
     * 用于生成请求ID
     */
    private static AtomicInteger atomicInteger = new AtomicInteger(1);
    /**
     * 包长度
     */
    private int lc;
    /**
     * 请求ID
     */
    private int requestId;
    /**
     * 命令码
     */
    private int cmd;
    /**
     * 数据
     */
    private byte[] data;
    /**
     * 协商密钥
     */
    private byte[] agreementKey;
    /**
     * 密文数据
     */
    private byte[] cipherData;


    public RequestMessage(int cmd, byte[] data, byte[] agreementKey) {
        this.cmd = cmd;
        this.data = data;
        this.agreementKey = agreementKey;
        lc = 12 + data.length;
        if (agreementKey != null) {
            lc = 12 + cipherData.length;
        }
        if(CmdConsts. == cmd) {
            requestId = 0;
        } else {
            requestId = atomicInteger.incrementAndGet();
        }
        if (agreementKey != null) {
            SM4 sm4Padding = new SM4(Mode.ECB, Padding.PKCS5Padding, agreementKey);
            cipherData = sm4Padding.encrypt(data);
            lc = 12 + cipherData.length;
        }
    }
}
