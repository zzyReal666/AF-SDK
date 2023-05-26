package com.af.device.impl;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.device.DeviceInfo;
import com.af.device.IAFTSDevice;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.utils.BytesBuffer;
import com.af.utils.SM4Utils;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 时间戳设备实现类, 单例模式 因为时间戳接口较少,没有分层,直接在该类中构造message
 * @since 2023/5/18 9:39
 */
public class AFTSDevice implements IAFTSDevice {
    private static final Logger logger = LoggerFactory.getLogger(AFTSDevice.class);


    /**
     * 通信客户端
     */
    @Getter
    private static AFNettyClient client = null;

    //私有化构造方法
    private AFTSDevice() {
    }

    //静态内部类单例
    private static class SingletonHolder {
        private static final AFTSDevice INSTANCE = new AFTSDevice();
    }

    //获取单例
    public static AFTSDevice getInstance(String host, int port, String passwd) {
        client = AFNettyClient.getInstance(host, port, passwd);
        return SingletonHolder.INSTANCE;
    }



    /**
     * 获取设备信息
     *
     * @return 设备信息
     * @throws AFCryptoException 获取设备信息异常
     */
    @Override
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        return null;
    }

    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * @throws AFCryptoException 获取随机数异常
     */
    @Override
    public byte[] getRandom(int length) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * 时间戳请求
     *
     * @param data       预加盖时间戳的用户信息
     * @param extendInfo 扩展信息（DER编码）
     * @param reqType    时间戳服务类型 0代表响应包含TSA证书 1代表响应不包含TSA证书
     * @param hashAlg    杂凑算法标识
     * @return ASN1结构请求体
     */
    @Override
    public byte[] tsRequest(byte[] data, byte[] extendInfo, int reqType, int hashAlg) throws AFCryptoException {
        logger.info("时间戳请求, data: {}, extendInfo: {}, reqType: {}, hashAlg: {}", data, extendInfo, reqType, hashAlg);
        byte[] param = new BytesBuffer()
                .append(data.length)
                .append(data)
                .append(reqType)
                .append(extendInfo == null ? 0 : extendInfo.length)
                .append(extendInfo)
                .append(hashAlg)
                .toBytes();
        param = SM4Utils.encrypt(ROOT_KEY, param);
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_CREATE_TS_REQUEST, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("时间戳请求失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("时间戳请求失败, 错误码: " + responseMessage.getHeader().getErrorCode() + ", 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * 时间戳响应
     *
     * @param asn1Request ASN1结构请求体
     * @param signAlg     签名算法标识
     * @return DER编码时间戳
     */
    @Override
    public byte[] tsResponse(byte[] asn1Request, int signAlg) throws AFCryptoException {
        logger.info("时间戳响应, asn1Request: {}, signAlg: {}", asn1Request, signAlg);
        byte[] param = new BytesBuffer()
                .append(asn1Request.length)
                .append(asn1Request)
                .append(signAlg)
                .toBytes();
        param = SM4Utils.encrypt(ROOT_KEY, param);
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_TS_RESPONSE, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("时间戳响应失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("时间戳响应失败, 错误码: " + responseMessage.getHeader().getErrorCode() + ", 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }

    /**
     * 时间戳请求并响应
     *
     * @param data       预加盖时间戳的用户信息
     * @param extendInfo 扩展信息（DER编码）
     * @param reqType    时间戳服务类型 0代表响应包含TSA证书 1代表响应不包含TSA证书
     * @param hashAlg    杂凑算法标识
     * @param signAlg    签名算法标识
     * @return DER编码时间戳
     */
    @Override
    public byte[] tsRequestAndResponse(byte[] data, byte[] extendInfo, int reqType, int hashAlg, int signAlg) throws AFCryptoException {
        byte[] requestData = tsRequest(data, extendInfo, reqType, hashAlg);
        return tsResponse(requestData, signAlg);
    }

    /**
     * 验证时间戳
     *
     * @param tsValue DER编码时间戳
     * @param hashAlg 杂凑算法标识
     * @param signAlg 签名算法标识
     * @param tsaCert TSA证书，对于不包含TSA证书的时间戳，需要指定证书
     * @return 验证结果
     */
    @Override
    public boolean tsVerify(byte[] tsValue, int hashAlg, int signAlg, byte[] tsaCert) throws AFCryptoException {
        logger.info("验证时间戳, tsValue: {}, hashAlg: {}, signAlg: {}, tsaCert: {}", tsValue, hashAlg, signAlg, tsaCert);
        byte[] param = new BytesBuffer()
                .append(tsValue.length)
                .append(tsValue)
                .append(signAlg)
                .append(hashAlg)
                .append(tsaCert == null ? 0 : tsaCert.length)
                .append(tsaCert)
                .toBytes();
        param = SM4Utils.encrypt(ROOT_KEY, param);
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_TS_VERIFY, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() == 0) {
            return true;
        }
        logger.error("验证时间戳失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
        return false;
    }

    /**
     * 获取时间戳主要信息
     *
     * @param tsValue DER编码时间戳
     * @return 返回数据格式为：TSA通用名|签发时间
     */
    @Override
    public String getTsInfo(byte[] tsValue) throws AFCryptoException {
        logger.info("获取时间戳主要信息, tsValue: {}", tsValue);
        byte[] param = new BytesBuffer()
                .append(tsValue.length)
                .append(tsValue)
                .toBytes();
        param = SM4Utils.encrypt(ROOT_KEY, param);
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GET_TS_INFO, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取时间戳主要信息失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取时间戳主要信息失败, 错误码: " + responseMessage.getHeader().getErrorCode() + ", 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        byte[] issue = responseMessage.getDataBuffer().readOneData();
        byte[] time = responseMessage.getDataBuffer().readOneData();
        return new String(issue, StandardCharsets.UTF_8) + "|" + new String(time, StandardCharsets.UTF_8);
    }

    /**
     * 获取指定的时间戳详细信息
     *
     * @param tsValue DER编码时间戳
     * @param subject 时间戳详细信息的项目编号
     * @return 指定信息
     */
    @Override
    public byte[] getTsDetail(byte[] tsValue, int subject) throws AFCryptoException {
        logger.info("获取指定的时间戳详细信息, tsValue: {}, subject: {}", tsValue, subject);
        byte[] param = new BytesBuffer()
                .append(tsValue.length)
                .append(tsValue)
                .append(subject)
                .toBytes();
        param = SM4Utils.encrypt(ROOT_KEY, param);
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GET_TS_DETAIL, param);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取指定的时间戳详细信息失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取指定的时间戳详细信息失败, 错误码: " + responseMessage.getHeader().getErrorCode() + ", 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }
}
