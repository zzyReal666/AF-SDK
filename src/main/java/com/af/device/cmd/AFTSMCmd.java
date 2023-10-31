package com.af.device.cmd;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.constant.TSMInfoFlag;
import com.af.exception.AFCryptoException;
import com.af.netty.NettyClient;
import com.af.utils.BytesBuffer;

import java.nio.charset.StandardCharsets;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/6/9 18:12
 */
public class AFTSMCmd extends AFCmd{

    public AFTSMCmd(NettyClient client, byte[] agKey) {
        super(client, agKey);
    }


    /**
     * 时间戳请求
     *
     * @param data       预加盖时间戳的用户信息
     * @param extendInfo 扩展信息（DER编码）
     * @param reqType    时间戳服务类型 0代表响应包含TSA证书 1代表响应不包含TSA证书
     * @param hashAlg    杂凑算法标识 SGD_SM3
     * @return ASN1结构请求体
     */

    public byte[] tsRequest(byte[] data, byte[] extendInfo, int reqType, int hashAlg) throws AFCryptoException { //success
        logger.info("时间戳请求, data: {}, extendInfo: {}, reqType: {}, hashAlg: {}", data, extendInfo, reqType, hashAlg);
        byte[] param = new BytesBuffer()
                .append(data.length)
                .append(data)
                .append(reqType)
                .append(extendInfo == null ? 0 : extendInfo.length)
                .append(extendInfo)
                .append(hashAlg)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_CREATE_TS_REQUEST, param, agKey);
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
     * @param signAlg     签名算法标识 SGD_SM3
     * @return DER编码时间戳
     */
    public byte[] tsResponse(byte[] asn1Request, int signAlg) throws AFCryptoException {
        logger.info("时间戳响应, asn1Request: {}, signAlg: {}", asn1Request, signAlg);
        byte[] param = new BytesBuffer()
                .append(asn1Request.length)
                .append(asn1Request)
                .append(signAlg)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_TS_RESPONSE, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("时间戳响应失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("时间戳响应失败, 错误码: " + responseMessage.getHeader().getErrorCode() + ", 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }



    /**
     * 验证时间戳
     *
     * @param tsValue DER编码时间戳
     * @param hashAlg 杂凑算法标识 SGD_SM3
     * @param signAlg 签名算法标识 SGD_SM2|SGD_SM2_1|SGD_SM2_2|SGD_SM2_3
     * @param tsaCert TSA证书，对于不包含TSA证书的时间戳，需要指定证书
     * @return 验证结果
     */
    public boolean tsVerify(byte[] tsValue, int signAlg,int hashAlg,  byte[] tsaCert) throws AFCryptoException {
        logger.info("验证时间戳, tsValue: {}, hashAlg: {}, signAlg: {}, tsaCertLen: {}", tsValue, hashAlg, signAlg, tsaCert == null ? 0 : tsaCert.length);
        byte[] param = new BytesBuffer()
                .append(tsValue.length)
                .append(tsValue)
                .append(signAlg)
                .append(hashAlg)
                .append(tsaCert == null ? 0 : tsaCert.length)
                .append(tsaCert)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_TS_VERIFY, param, agKey);
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
    public String getTsInfo(byte[] tsValue) throws AFCryptoException {
        logger.info("获取时间戳主要信息, tsValue: {}", tsValue);
        byte[] param = new BytesBuffer()
                .append(tsValue.length)
                .append(tsValue)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GET_TS_INFO, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取时间戳主要信息失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取时间戳主要信息失败, 错误码: " + responseMessage.getHeader().getErrorCode() + ", 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        BytesBuffer dataBuffer = responseMessage.getDataBuffer();
        byte[] issue = dataBuffer.readOneData();
        byte[] time = dataBuffer.readOneData();
        return new String(issue, StandardCharsets.UTF_8) + "|" + new String(time, StandardCharsets.UTF_8);
    }

    /**
     * 获取指定的时间戳详细信息
     *
     * @param tsValue DER编码时间戳
     * @param subject 时间戳详细信息的项目编号
     * @return 指定信息
     */
    public byte[] getTsDetail(byte[] tsValue, TSMInfoFlag subject) throws AFCryptoException {
        logger.info("获取指定的时间戳详细信息, tsValue: {}, subject: {}", tsValue, subject.getValue());
        byte[] param = new BytesBuffer()
                .append(tsValue.length)
                .append(tsValue)
                .append(subject.getValue())
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GET_TS_DETAIL, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取指定的时间戳详细信息失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取指定的时间戳详细信息失败, 错误码: " + responseMessage.getHeader().getErrorCode() + ", 错误信息: " + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }
}
