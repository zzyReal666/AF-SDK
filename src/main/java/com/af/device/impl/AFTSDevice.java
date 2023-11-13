package com.af.device.impl;

import com.af.constant.Algorithm;
import com.af.constant.TSMInfoFlag;
import com.af.device.DeviceInfo;
import com.af.device.IAFDevice;
import com.af.device.IAFTSDevice;
import com.af.device.cmd.AFTSMCmd;
import com.af.exception.AFCryptoException;
import com.af.netty.NettyClient;
import com.af.nettyNew.NettyClientChannels;
import com.af.utils.BytesOperate;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 时间戳设备实现类, 单例模式 因为时间戳接口较少,没有分层,直接在该类中构造message
 * @since 2023/5/18 9:39
 */
@Setter
@Getter
@ToString
public class AFTSDevice implements IAFTSDevice {
    private static final Logger logger = LoggerFactory.getLogger(AFTSDevice.class);
    private NettyClient client = null;
    private byte[] agKey;
    private AFTSMCmd cmd;
    //私有化构造方法
    private AFTSDevice() {
    }
    //静态内部类单例
    private static class SingletonHolder {
        private static final Map<String, AFTSDevice> INSTANCE = new ConcurrentHashMap<>();
    }
    public static class Builder {
        //必要参数
        private final String host;
        private final int port;
        private final String passwd;

        //构造
        public Builder(String host, int port, String passwd) {
            this.host = host;
            this.port = port;
            this.passwd = passwd;
        }

        //可选参数

        /**
         * 是否协商密钥
         */
        private boolean isAgKey = true;
        /**
         * 连接超时时间 单位毫秒
         */
        private int connectTimeOut = 5000;

        /**
         * 响应超时时间 单位毫秒
         */
        private int responseTimeOut = 10000;

        /**
         * 重试次数
         */
        private int retryCount = 3;

        /**
         * 重试间隔 单位毫秒
         */
        private int retryInterval = 5000;

        /**
         * 缓冲区大小
         */
        private int bufferSize = 1024 * 1024;

        /**
         * 通道数量
         */
        private int channelCount = 10;

        public Builder isAgKey(boolean isAgKey) {
            this.isAgKey = isAgKey;
            return this;
        }

        public Builder connectTimeOut(int connectTimeOut) {
            this.connectTimeOut = connectTimeOut;
            return this;
        }

        public Builder responseTimeOut(int responseTimeOut) {
            this.responseTimeOut = responseTimeOut;
            return this;
        }

        public Builder retryCount(int retryCount) {
            this.retryCount = retryCount;
            return this;
        }

        public Builder retryInterval(int retryInterval) {
            this.retryInterval = retryInterval;
            return this;
        }

        public Builder bufferSize(int bufferSize) {
            this.bufferSize = bufferSize;
            return this;
        }

        public Builder channelCount(int channelCount) {
            this.channelCount = channelCount;
            return this;
        }

        public AFTSDevice build() {

            if (SingletonHolder.INSTANCE.containsKey(host + ":" + port)) {
                return SingletonHolder.INSTANCE.get(host + ":" + port);
            }
            AFTSDevice instance = new AFTSDevice();
            NettyClientChannels build = new NettyClientChannels.Builder(host, port, passwd, IAFDevice.generateTaskNo())
                    .timeout(connectTimeOut)
                    .responseTimeout(responseTimeOut)
                    .retryCount(retryCount)
                    .retryInterval(retryInterval)
                    .bufferSize(bufferSize)
                    .channelCount(channelCount)
                    .build();
            instance.setClient(build);
            instance.setCmd(new AFTSMCmd(build, instance.agKey));
            SingletonHolder.INSTANCE.put(host + ":" + port, instance);
            if (isAgKey && instance.getAgKey() == null) {
                instance.setAgKey();
            }
            return instance;
        }
    }

    /**
     * 协商密钥
     */
    public AFTSDevice setAgKey() {
        this.agKey = this.keyAgreement(client);
        cmd.setAgKey(agKey);
        logger.info("协商密钥成功");
        return this;
    }


    /**
     * 获取设备信息 时间戳服务器不开放
     */
    @Override
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        return null;
    }

    /**
     * 获取随机数 时间戳服务器不开放该接口
     */
    @Override
    public byte[] getRandom(int length) throws AFCryptoException {
        return new byte[0];
    }

    @Override
    public void close() {
        SingletonHolder.INSTANCE.remove(client.getAddr());
    }


    /**
     * 时间戳请求
     *
     * @param data    预加盖时间戳的用户信息
     * @param reqType 时间戳服务类型 0代表响应包含TSA证书 1代表响应不包含TSA证书
     * @return 时间戳请求信息数据（DER 编码）
     */
    public byte[] tsRequest(byte[] data, int reqType) throws AFCryptoException {
        if (data == null || data.length == 0) {
            throw new AFCryptoException("时间戳请求数据为空,data is null");
        }
        if (reqType != 0 && reqType != 1) {
            throw new AFCryptoException("时间戳请求类型错误,reqType is invalid");
        }
        return cmd.tsRequest(data, null, reqType, Algorithm.SGD_SM3.getValue());
    }

    /**
     * 时间戳响应
     *
     * @param asn1Request 时间戳请求信息数据（DER 编码）
     * @return 时间戳响应数据（DER 编码）
     */
    public byte[] tsResponse(byte[] asn1Request) throws AFCryptoException {
        if (asn1Request == null || asn1Request.length == 0) {
            throw new AFCryptoException("时间戳请求数据为空,asn1Request is null");
        }
        return cmd.tsResponse(asn1Request, Algorithm.SGD_SM3.getValue());
    }

    /**
     * 时间戳请求并响应
     *
     * @param data    预加盖时间戳的用户信息
     * @param reqType 时间戳服务类型 0代表响应包含TSA证书 1代表响应不包含TSA证书
     * @return DER编码时间戳
     */
    public byte[] tsRequestAndResponse(byte[] data, int reqType) throws AFCryptoException {
        byte[] requestData = tsRequest(data, reqType);
        return tsResponse(requestData);
    }

    /**
     * 时间戳验证
     *
     * @param tsValue  时间戳响应信息
     * @param signAlg  签名算法标识（SGD_SM2|SGD_SM2_1|SGD_SM2_2|SGD_SM2_3）
     * @param signCert TSA证书 Base64编码
     */
    public boolean tsVerify(byte[] tsValue, int signAlg, byte[] signCert) throws AFCryptoException {
        if (tsValue == null || tsValue.length == 0) {
            throw new AFCryptoException("tsValue is null");
        }
        signCert = null == signCert ? null : BytesOperate.base64DecodeCert(new String(signCert));
        return cmd.tsVerify(tsValue, signAlg, Algorithm.SGD_SM3.getValue(), signCert);
    }


    /**
     * 获取时间戳信息
     *
     * @param tsValue 时间戳响应信息
     */
    public String getTsInfo(byte[] tsValue) throws AFCryptoException {
        if (tsValue == null || tsValue.length == 0) {
            throw new AFCryptoException("tsValue is null");
        }
        return cmd.getTsInfo(tsValue);
    }

    /**
     * 获取时间戳详细信息
     *
     * @param tsValue  时间戳响应信息
     * @param infoFlag 信息标识
     * @return 时间戳详细信息
     */
    public byte[] getTsDetailInfo(byte[] tsValue, TSMInfoFlag infoFlag) throws AFCryptoException {
        if (tsValue == null || tsValue.length == 0) {
            throw new AFCryptoException("tsValue is null");
        }
        return cmd.getTsDetail(tsValue, infoFlag);
    }
}
