package com.af.device;

import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 时间戳设备接口
 * @since 2023/5/18 9:32
 */
public interface IAFTSDevice extends IAFDevice {


    /**
     * 时间戳请求
     *
     * @param data       预加盖时间戳的用户信息
     * @param extendInfo 扩展信息（DER编码）
     * @param reqType    时间戳服务类型 0代表响应包含TSA证书 1代表响应不包含TSA证书
     * @param hashAlg    杂凑算法标识
     * @return ASN1结构请求体
     */
    byte[] tsRequest(byte[] data, byte[] extendInfo, int reqType, int hashAlg) throws AFCryptoException;


    /**
     * 时间戳响应
     *
     * @param asn1Request ASN1结构请求体
     * @param signAlg     签名算法标识
     * @return DER编码时间戳
     */
    byte[] tsResponse(byte[] asn1Request, int signAlg) throws AFCryptoException;


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
    byte[] tsRequestAndResponse(byte[] data, byte[] extendInfo, int reqType, int hashAlg, int signAlg) throws AFCryptoException;


    /**
     * 验证时间戳
     *
     * @param tsValue DER编码时间戳
     * @param hashAlg 杂凑算法标识
     * @param signAlg 签名算法标识
     * @param tsaCert TSA证书，对于不包含TSA证书的时间戳，需要指定证书
     * @return 验证结果
     */
     boolean tsVerify(byte[] tsValue, int hashAlg, int signAlg, byte[] tsaCert) throws AFCryptoException;


    /**
     * 获取时间戳主要信息
     *
     * @param tsValue DER编码时间戳
     * @return 返回数据格式为：TSA通用名|签发时间
     */
     String getTsInfo(byte[] tsValue) throws AFCryptoException;


    /**
     * 获取指定的时间戳详细信息
     *
     * @param tsValue DER编码时间戳
     * @param subject 时间戳详细信息的项目编号
     * @return 指定信息
     */
     byte[] getTsDetail(byte[] tsValue, int subject) throws AFCryptoException;


}
