package com.af.device.impl;

import com.af.device.DeviceInfo;
import com.af.device.IAFDevice;
import com.af.exception.AFCryptoException;

import java.io.IOException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 签名验签服务器 设备实现类
 * @since 2023/5/16 9:12
 */
public class AFSVDevice implements IAFDevice {

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
    public byte[] tsRequest(byte[] data, byte[] extendInfo, int reqType, int hashAlg) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * 时间戳响应
     *
     * @param asn1Request ASN1结构请求体
     * @param signAlg     签名算法标识
     * @return DER编码时间戳
     */
    public byte[] tsResponse(byte[] asn1Request, int signAlg) throws IOException {
        return new byte[0];
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
    public byte[] tsRequestAndResponse(byte[] data, byte[] extendInfo, int reqType, int hashAlg, int signAlg) throws IOException {
        return new byte[0];
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
    public boolean tsVerify(byte[] tsValue, int hashAlg, int signAlg, byte[] tsaCert) throws IOException {
        return false;
    }
}
