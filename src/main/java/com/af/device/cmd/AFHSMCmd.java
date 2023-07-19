package com.af.device.cmd;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.Algorithm;
import com.af.constant.CMDCode;
import com.af.constant.ModulusLength;
import com.af.device.DeviceInfo;
import com.af.exception.AFCryptoException;
import com.af.netty.NettyClient;
import com.af.nettyNew.NettyClientChannels;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/29 11:13
 */
public class AFHSMCmd extends AFCmd {
    int count = client instanceof NettyClientChannels ? ((NettyClientChannels) client).getNettyChannelPool().getChannelCount() : 1;

    public AFHSMCmd(NettyClient client, byte[] agKey) {
        super(client, agKey);
    }


    /**
     * 获取设备信息
     *
     * @return 设备信息
     * @throws AFCryptoException 获取设备信息异常
     */
    public DeviceInfo getDeviceInfo() throws AFCryptoException {
        logger.info("获取设备信息");
        RequestMessage req = new RequestMessage(CMDCode.CMD_DEVICEINFO, null, agKey);
        //发送请求
        ResponseMessage resp = client.send(req);
        if (resp.getHeader().getErrorCode() != 0) {
            logger.error("获取设备信息错误,错误码:{},错误信息:{}", resp.getHeader().getErrorCode(), resp.getHeader().getErrorInfo());
        }
        DeviceInfo info = new DeviceInfo();
        info.decode(resp.getDataBuffer().readOneData());
        return info;
    }

    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * @throws AFCryptoException 获取随机数异常
     */
    public byte[] getRandom(int length) throws AFCryptoException {
        logger.info("HSM-CMD-获取随机数 length:{}", length);
        if (length <= 0) {
            logger.error("获取随机数错误,随机数长度错误 length:{}", length);
            throw new AFCryptoException("获取随机数错误,随机数长度错误");
        }
        byte[] param = new BytesBuffer().append(length).toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATERANDOM, param, agKey);
        ResponseMessage resp;
        //发送请求
        try {
            resp = client.send(req);
        } catch (Exception e) {
            logger.error("获取随机数错误", e);
            throw new AFCryptoException("获取随机数异常", e);
        }
        if (resp == null || resp.getHeader().getErrorCode() != 0) {
            logger.error("获取随机数错误,无响应或者响应码错误 response:{} ErrorCode:{}", resp == null ? "null" : resp.toString(), resp == null ? "null" : resp.getHeader().getErrorCode());
            throw new AFCryptoException("获取随机数异常");
        }
        return resp.getDataBuffer().readOneData();
    }

//    /**
//     * <p> 获取RSA签名公钥信息 </p>
//     *
//     * @param index ：密钥索引
//     * @return 返回RSA签名数据结构
//     */
//    public byte[] getRSASignPublicKey(int index) throws AFCryptoException {
//        logger.info("HSM-CMD-获取RSA签名公钥信息, index:{}", index);
//        byte[] param = new BytesBuffer()
//                .append(index)
//                .append(ConstantNumber.SGD_RSA_SIGN)
//                .toBytes();
//        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTSIGNPUBLICKEY_RSA, param, agKey);
//        ResponseMessage res = client.send(req);
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-获取RSA签名公钥信息失败, index:{}, 错误码:{},错误信息:{}", index, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-获取RSA签名公钥信息失败, index:" + index + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        return res.getDataBuffer().readOneData();
//    }
//
//    /**
//     * <p> 获取RSA加密公钥信息 </p>
//     *
//     * @param index ： 密钥索引
//     * @return 返回RSA加密数据结构
//     */
//    public byte[] getRSAEncPublicKey(int index) throws AFCryptoException {
//        logger.info("HSM-CMD-获取RSA加密公钥信息, index:{}", index);
//        byte[] param = new BytesBuffer()
//                .append(index)
//                .append(ConstantNumber.SGD_RSA_ENC)
//                .toBytes();
//        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTENCPUBLICKEY_RSA, param, agKey);
//        ResponseMessage res = client.send(req);
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-获取RSA加密公钥信息失败, index:{}, 错误码:{},错误信息:{}", index, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-获取RSA加密公钥信息失败, index:" + index + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        return res.getDataBuffer().readOneData();
//    }

//    /**
//     * <p> 生成RSA密钥对信息 </p>
//     *
//     * @param bits : 位长，1024 or 2048
//     * @return 返回RSA密钥对数据结构
//     */
//    public RSAKeyPair generateRSAKeyPair(int bits) throws AFCryptoException {
//        logger.info("HSM-CMD-生成RSA密钥对信息, bits:{}", bits);
//        byte[] param = new BytesBuffer()
//                .append(ConstantNumber.SGD_RSA)
//                .append(bits)
//                .toBytes();
//        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATEKEYPAIR_RSA, param, agKey);
//        ResponseMessage res = client.send(req);
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-生成RSA密钥对信息失败, bits:{}, 错误码:{},错误信息:{}", bits, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-生成RSA密钥对信息失败, bits:" + bits + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        //公钥长度与公钥数据
//        int pubKeyLen = BytesOperate.bytes2int(res.getData());
//        byte[] pubKeyData = getBytes(res.getData(), 4, pubKeyLen);
//
//        //私钥长度与私钥数据
//        int privateKeyLen = BytesOperate.bytes2int(res.getData(), 4 + pubKeyLen);
//        byte[] privateKeyData = getBytes(res.getData(), 4 + pubKeyLen + 4, privateKeyLen);
//
//        //解析公钥
//        RSAPubKey pubKey = new RSAPubKey();
//        pubKey.decode(pubKeyData);
//
//        //解析私钥
//        RSAPriKey priKey = new RSAPriKey();
//        priKey.decode(privateKeyData);
//
//        return new RSAKeyPair(pubKey, priKey);
//    }
//
//    /**
//     * <p> RSA外部加密运算 </p>
//     *
//     * @param publicKey ：RSA公钥信息
//     * @param data      : 原始数据
//     * @return ：返回运算结果
//     */
//
//    public byte[] RSAExternalEncode(RSAPubKey publicKey, byte[] data) throws AFCryptoException {
//        logger.info("HSM-CMD-RSA外部加密运算, publicKey:{}, dataLen:{}", publicKey, data.length);
//        byte[] param = new BytesBuffer()
//                .append(0)
//                .append(0)
//                .append(0)
//                .append(publicKey.size())
//                .append(publicKey.encode())
//                .append(data.length)
//                .append(data)
//                .toBytes();
//        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPUBLICKEYOPERATION_RSA, param, agKey);
//        ResponseMessage res = client.send(req);
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-RSA外部加密运算失败, dataLen:{}, 错误码:{},错误信息:{}", data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-RSA外部加密运算失败, dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        return res.getDataBuffer().readOneData();
//    }
//
//    /**
//     * <p> RSA外部解密运算 </p>
//     *
//     * @param prvKey ：RSA私钥信息
//     * @param data   : 加密数据
//     * @return ：返回运算结果
//     */
//
//    public byte[] RSAExternalDecode(RSAPriKey prvKey, byte[] data) throws AFCryptoException {
//        logger.info("HSM-CMD-RSA外部解密运算, prvKey:{}, dataLen:{}", prvKey, data.length);
//        byte[] param = new BytesBuffer()
//                .append(0)
//                .append(0)
//                .append(0)
//                .append(prvKey.size())
//                .append(prvKey.encode())
//                .append(data.length)
//                .append(data)
//                .toBytes();
//        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPRIVATEKEYOPERATION_RSA, param, agKey);
//        ResponseMessage res = client.send(req);
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-RSA外部解密运算失败, dataLen:{}, 错误码:{},错误信息:{}", data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-RSA外部解密运算失败, dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        return res.getDataBuffer().readOneData();
//    }
//
//    /**
//     * <p> RSA外部签名运算 </p>
//     *
//     * @param prvKey ：RSA私钥信息
//     * @param data   : 原始数据
//     * @return ：返回运算结果
//     */
//
//    public byte[] RSAExternalSign(RSAPriKey prvKey, byte[] data) throws AFCryptoException {
//        logger.info("HSM-CMD-RSA外部签名运算, prvKey:{}, dataLen:{}", prvKey, data.length);
//        byte[] param = new BytesBuffer()
//                .append(0)
//                .append(0)
//                .append(0)
//                .append(prvKey.size())
//                .append(prvKey.encode())
//                .append(data.length)
//                .append(data)
//                .toBytes();
//
//        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPRIVATEKEYOPERATION_RSA, param, agKey);
//        ResponseMessage res = client.send(req);
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-RSA外部签名运算失败, dataLen:{}, 错误码:{},错误信息:{}", data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-RSA外部签名运算失败, dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        return res.getDataBuffer().readOneData();
//    }
//
//    /**
//     * <p> RSA外部验证签名运算 </p>
//     *
//     * @param publicKey ：RSA公钥信息
//     * @param data      : 签名数据
//     * @param rawData   : 原始数据
//     * @return ：true: 验证成功，false：验证失败
//     */
//
//    public boolean RSAExternalVerify(RSAPubKey publicKey, byte[] data, byte[] rawData) throws AFCryptoException {
//        logger.info("HSM-CMD-RSA外部验证签名运算, publicKey:{}, dataLen:{}, rawDataLen:{}", publicKey, data.length, rawData.length);
//        byte[] param = new BytesBuffer()
//                .append(0)
//                .append(0)
//                .append(0)
//                .append(publicKey.size())
//                .append(publicKey.encode())
//                .append(data.length)
//                .append(data)
//                .toBytes();
//
//        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPUBLICKEYOPERATION_RSA, param, agKey);
//        ResponseMessage res = client.send(req);
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-RSA外部验证签名运算失败, dataLen:{}, rawDataLen:{}, 错误码:{},错误信息:{}", data.length, rawData.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-RSA外部验证签名运算失败, dataLen:" + data.length + ", rawDataLen:" + rawData.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        byte[] bytes = res.getDataBuffer().readOneData();
//        return Arrays.equals(bytes, rawData);
//    }
//
//    /**
//     * <p> RSA内部加密运算 </p>
//     *
//     * @param index ：RSA内部密钥索引
//     * @param data  : 原始数据
//     * @return ：返回运算结果
//     */
//
//    public byte[] RSAInternalEncode(int index, byte[] data) throws AFCryptoException {
//        logger.info("HSM-CMD-RSA内部加密运算, index:{}, dataLen:{}", index, data.length);
//        byte[] param = new BytesBuffer()
//                .append(index)
//                .append(ConstantNumber.SGD_RSA_ENC)
//                .append(0)
//                .append(0)
//                .append(data.length)
//                .append(data)
//                .toBytes();
//        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_INTERNALPUBLICKEYOPERATION_RSA, param, agKey));
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-RSA内部加密运算失败, index:{}, dataLen:{}, 错误码:{},错误信息:{}", index, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-RSA内部加密运算失败, index:" + index + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        return res.getDataBuffer().readOneData();
//    }
//
//    /**
//     * <p> RSA内部解密运算 </p>
//     *
//     * @param index ：RSA内部密钥索引
//     * @param data  : 加密数据
//     * @return ：返回运算结果
//     */
//
//    public byte[] RSAInternalDecode(int index, byte[] data) throws AFCryptoException {
//        logger.info("HSM-CMD-RSA内部解密运算, index:{}, dataLen:{}", index, data.length);
//        byte[] param = new BytesBuffer()
//                .append(index)
//                .append(ConstantNumber.SGD_RSA_ENC)
//                .append(0)
//                .append(0)
//                .append(data.length)
//                .append(data)
//                .toBytes();
//        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_INTERNALPRIVATEKEYOPERATION_RSA, param, agKey));
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-RSA内部解密运算失败, index:{}, dataLen:{}, 错误码:{},错误信息:{}", index, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-RSA内部解密运算失败, index:" + index + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        return res.getDataBuffer().readOneData();
//    }
//
//    /**
//     * <p> RSA内部签名运算</p>
//     *
//     * @param index ：RSA内部密钥索引
//     * @param data  : 原始数据
//     * @return ：返回运算结果
//     */
//
//    public byte[] RSAInternalSign(int index, byte[] data) throws AFCryptoException {
//        logger.info("HSM-CMD-RSA内部签名运算, index:{}, dataLen:{}", index, data.length);
//        byte[] param = new BytesBuffer()
//                .append(index)
//                .append(ConstantNumber.SGD_RSA_SIGN)
//                .append(0)
//                .append(0)
//                .append(data.length)
//                .append(data)
//                .toBytes();
//        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_INTERNALPRIVATEKEYOPERATION_RSA, param, agKey));
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-RSA内部签名运算失败, index:{}, dataLen:{}, 错误码:{},错误信息:{}", index, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-RSA内部签名运算失败, index:" + index + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        return res.getDataBuffer().readOneData();
//
//    }
//
//    /**
//     * <p> RSA内部验证签名运算 </p>
//     *
//     * @param index   ：RSA内部密钥索引
//     * @param data    : 签名数据
//     * @param rawData : 原始数据
//     * @return ：true: 验证成功，false：验证失败
//     */
//    public boolean RSAInternalVerify(int index, byte[] data, byte[] rawData) throws AFCryptoException {
//        logger.info("HSM-CMD-RSA内部验证签名运算, index:{}, dataLen:{}, rawDataLen:{}", index, data.length, rawData.length);
//        byte[] param = new BytesBuffer()
//                .append(index)
//                .append(ConstantNumber.SGD_RSA_SIGN)
//                .append(0)
//                .append(0)
//                .append(data.length)
//                .append(data)
//                .toBytes();
//        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_INTERNALPUBLICKEYOPERATION_RSA, param, agKey));
//        if (res.getHeader().getErrorCode() != 0) {
//            logger.error("HSM-CMD-RSA内部验证签名运算失败, index:{}, dataLen:{}, rawDataLen:{}, 错误码:{},错误信息:{}", index, data.length, rawData.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
//            throw new AFCryptoException("HSM-CMD-RSA内部验证签名运算失败, index:" + index + ", dataLen:" + data.length + ", rawDataLen:" + rawData.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
//        }
//        byte[] bytes = res.getDataBuffer().readOneData();
//        return Arrays.equals(bytes, rawData);
//    }


    // ===================================根据协议实现 通信接口===================================


    /**
     * 导出公钥信息
     *
     * @param index     密钥索引
     * @param algorithm 算法标识
     * @return 4+N
     */
    public byte[] exportPublicKey(int index, Algorithm algorithm) throws AFCryptoException {
        logger.info("HSM-导出公钥信息, index: {}, keyType: {}", index, algorithm);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(algorithm.getValue())
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.EXPORT_PUBLIC_KEY, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-导出公钥信息,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-导出公钥信息,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 生成密钥对
     *
     * @param algorithm     算法标识SGD_RSA|SGD_SM2|SGD_SM2_1|SGD_SM2_2|SGD_SM2_3
     * @param modulusLength 模量长度 RSA 1024|2048|   SM2 256
     * @return 1、4 字节公钥信息长度
     * 2、公钥信息
     * 3、4 字节私钥信息长度
     * 4、私钥信息
     */
    public byte[] generateKeyPair(Algorithm algorithm, ModulusLength modulusLength) throws AFCryptoException {
        logger.info("SV-生成密钥对, keyType: {}, modulusLength: {}", algorithm, modulusLength.getLength());
        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(modulusLength.getLength())
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATEKEYPAIR_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-生成密钥对,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-生成密钥对,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }

    /**
     * 生成会话密钥
     *
     * @param algorithm        算法标识 SGD_RSA_ENC|SGD_SM2_2
     * @param keyIndex         密钥索引 外部密钥索引为 0
     * @param sessionKeyLength 会话密钥长度
     * @param publicKey        外部公钥
     * @return 1、4 字节会话密钥 ID
     * 2、4 字节加密信息长度
     * 3、加密信息
     */
    public byte[] generateSessionKey(Algorithm algorithm, int keyIndex, int sessionKeyLength, byte[] publicKey) throws AFCryptoException {
        logger.info("HSM-CMD-生成会话密钥, keyType: {}, keyIndex: {}, keyLength: {},publicKeyLength:{}", algorithm, keyIndex, sessionKeyLength,null == publicKey ? 0 : publicKey.length);
        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(keyIndex)
                .append(sessionKeyLength)
                .append(null == publicKey ? 0 : publicKey.length)
                .append(publicKey)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATEKEY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-生成会话密钥,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-生成会话密钥,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();

    }

    /**
     * 导入会话密钥密文
     *
     * @param algorithm 算法标识 SGD_RSA_ENC|SGD_SM2_2
     * @param keyIndex  密钥索引
     * @param data      密钥密文
     * @return 4个字节会话密钥 ID
     */
    public byte[] importSessionKey(Algorithm algorithm, int keyIndex, byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-导入会话密钥密文, keyType: {}, keyIndex: {}, keyDataLen: {}", algorithm, keyIndex, data.length);
        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(keyIndex)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_IMPORTKEY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-导入会话密钥密文,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-导入会话密钥密文,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }

    /**
     * 数字信封转换
     *
     * @param algorithm 算法标识 SGD_RSA_ENC|SGD_SM2_3
     * @param keyIndex  密钥索引
     * @param pubKey    公钥
     * @param data      密文
     * @return 加密信息 4+N
     */
    public byte[] convertEnvelope(Algorithm algorithm, int keyIndex, byte[] pubKey, byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-数字信封转换, keyType: {}, keyIndex: {}, pubKey: {}, data: {}", algorithm, keyIndex, pubKey, data);
        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(keyIndex)
                .append(pubKey.length)
                .append(pubKey)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_CONVERTKEY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-数字信封转换,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-数字信封转换,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * 生成会话密钥（使用对称密钥）
     *
     * @param algorithm SGD_RSA_ENC|SGD_SM2_2
     * @param keyIndex  密钥索引
     * @param keyLength 密钥长度
     * @return 1、4 字节会话密钥 ID
     * 2、4 字节加密信息长度
     * 3、加密信息
     */
    public byte[] generateSessionKeyBySym(Algorithm algorithm, int keyIndex, int keyLength) throws AFCryptoException {
        logger.info("HSM-CMD-生成会话密钥（使用对称密钥）, keyType: {}, keyIndex: {}, keyLength: {}", algorithm, keyIndex, keyLength);
        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(keyIndex)
                .append(keyLength)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATEKEYWITHKEK, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-生成会话密钥（使用对称密钥）,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-生成会话密钥（使用对称密钥）,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }


    /**
     * 导入会话密钥密文（使用对称密钥）
     *
     * @param algorithm 算法标识 SGD_SM1_ECB|SGD_SMS4_ECB
     * @param keyIndex  密钥索引
     * @param keyData   密钥密文
     * @return 1、4 字节会话密钥 ID
     * 2、4 字节导入会话密钥长度
     */
    public byte[] importSessionKeyBySym(Algorithm algorithm, int keyIndex, byte[] keyData) throws AFCryptoException {
        logger.info("HSM-CMD-导入会话密钥密文（使用对称密钥）, keyType: {}, keyIndex: {}, keyDataLen: {}", algorithm, keyIndex, keyData.length);
        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(keyIndex)
                .append(keyData.length)
                .append(keyData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_IMPORTKEYWITHKEK, param, agKey);
        ResponseMessage res = null;
        for (int i = 0; i < count; i++) {
            res = client.send(req);
            if (res.getHeader().getErrorCode() != 0) {
                logger.error("HSM-CMD-导入会话密钥密文（使用对称密钥）,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
                throw new AFCryptoException("HSM-CMD-导入会话密钥密文（使用对称密钥）,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
            }
        }
        if (res == null) {
            throw new AFCryptoException("HSM-CMD-导入会话密钥密文（使用对称密钥）,错误码:9999,错误信息:响应为空");
        }
        return res.getData();
    }

    /**
     * 释放密钥信息
     *
     * @param keyIndex 密钥索引
     */
    public void freeKey(int keyIndex) throws AFCryptoException {
        logger.info("HSM-CMD-释放密钥信息, keyIndex: {}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_DESTROYKEY, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-释放密钥信息,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-释放密钥信息,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
    }

    /**
     * 生成协商数据
     *
     * @param keyIndex  密钥索引
     * @param keyLength 密钥模长
     * @param id        发起方ID
     * @return 1、4 字节公钥数据长度
     * 2、公钥数据
     * 3、4 字节临时公钥数据长度
     * 4、临时公钥数据
     */
    public byte[] generateAgreementData(int keyIndex, ModulusLength keyLength, byte[] id) throws AFCryptoException {
        logger.info("HSM-CMD-生成协商数据, keyIndex: {}, keyLength: {}, id: {}", keyIndex, keyLength, id);
        byte[] param = new BytesBuffer()
                .append(1)
                .append(keyIndex)
                .append(keyLength.getLength())
                .append(id.length)
                .append(id)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_AGREEMENT, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-生成协商数据,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-生成协商数据,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }

    /**
     * 生成协商数据及密钥
     *
     * @param keyIndex  密钥索引
     * @param pubKey    公钥数据
     * @param temPubKey 临时公钥数据
     * @param id        发起方ID
     * @param peerId    对方ID
     * @return 1、4 字节会话 ID
     * 2、4 字节回复方公钥数据长度
     * 3、回复方公钥数据
     * 4、4 字节回复方临时公钥数据长度
     * 5、回复方临时公钥数据
     */
    public byte[] generateAgreementDataAndKey(int keyIndex, ModulusLength keyLength, byte[] pubKey, byte[] temPubKey, byte[] id, byte[] peerId) throws AFCryptoException {
        logger.info("HSM-CMD-生成协商数据及密钥, keyIndex: {}, keyLength: {}, id: {}, peerId: {}", keyIndex, keyLength, id, peerId);
        byte[] param = new BytesBuffer()
                .append(2)
                .append(keyIndex)
                .append(keyLength.getLength())
                .append(pubKey.length)
                .append(pubKey)
                .append(temPubKey.length)
                .append(temPubKey)
                .append(id.length)
                .append(id)
                .append(peerId.length)
                .append(peerId)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_AGREEMENT, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-生成协商数据及密钥,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-生成协商数据及密钥,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }

    /**
     * 生成协商密钥
     *
     * @param pubKey    公钥数据
     * @param temPubKey 临时公钥数据
     * @param peerId    对方ID
     * @return 1、4 字节会话 ID
     */
    public byte[] generateAgreementKey(byte[] pubKey, byte[] temPubKey, byte[] peerId) throws AFCryptoException {
        logger.info("HSM-CMD-生成协商密钥, pubKey: {}, temPubKey: {}, id: {}", pubKey, temPubKey, peerId);
        byte[] param = new BytesBuffer()
                .append(3)
                .append(pubKey.length)
                .append(pubKey)
                .append(temPubKey.length)
                .append(temPubKey)
                .append(peerId.length)
                .append(peerId)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_AGREEMENT, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-生成协商密钥,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-生成协商密钥,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }


    /**
     * RSA 公钥操作  加密 | 验签
     *
     * @param keyIndex  密钥索引 外部密钥传0
     * @param pubKey    公钥
     * @param algorithm 算法标识  SGD_RSA_ENC|SGD_RSA_SIGN
     * @param data      数据
     * @return 4+n
     */
    public byte[] rsaPublicKeyOperation(int keyIndex, RSAPubKey pubKey, Algorithm algorithm, byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-RSA 公钥操作, keyIndex: {}, pubKey: {}, keyType: {}, data: {}", keyIndex, pubKey, algorithm, data);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(algorithm.getValue())
                .append(0)
                .append(null == pubKey ? 0 : pubKey.size())
                .append(null == pubKey ? null : pubKey.encode())
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.RSA_PUBLIC_KEY_OPERATE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-RSA 公钥操作,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-RSA 公钥操作,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * RSA 私钥操作  解密 | 签名
     *
     * @param keyIndex  密钥索引 外部密钥传0
     * @param priKey    私钥
     * @param algorithm 算法标识 SGD_RSA_ENC|SGD_RSA_SIGN
     * @param data      数据
     */
    public byte[] rsaPrivateKeyOperation(int keyIndex, RSAPriKey priKey, Algorithm algorithm, byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-RSA 私钥操作, keyIndex: {}, priKey: {}, keyType: {}, data: {}", keyIndex, priKey, algorithm, data);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(algorithm.getValue())
                .append(0)
                .append(null == priKey ? 0 : priKey.size())
                .append(null == priKey ? null : priKey.encode())
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.RSA_PRIVATE_KEY_OPERATE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-RSA 私钥操作,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-RSA 私钥操作,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * SM2 签名 内部私钥 1 | 外部私钥 0
     *
     * @param keyIndex 密钥索引 外部密钥传-1
     * @param priKey   私钥 内部密钥传null
     * @param data     数据 长度固定为 32 字节 取SM3摘要
     * @return 4+n
     */
    public byte[] sm2Sign(int keyIndex, byte[] priKey, byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-SM2 签名, keyIndex: {}, priKey: {}, data: {}", keyIndex, priKey, data);
        BytesBuffer buffer = new BytesBuffer();
        if (-1 != keyIndex && null == priKey) { //内部密钥
            buffer.append(1)
                    .append(keyIndex)
                    .append(data.length)   //取SM3摘要
                    .append(data);
        } else if (-1 == keyIndex && null != priKey) { //外部密钥
            buffer.append(0)
                    .append(Algorithm.SGD_SM2_1.getValue())
                    .append(0)

                    .append(priKey.length)
                    .append(priKey)

                    .append(data.length)   //取SM3摘要
                    .append(data);
        } else {
            throw new AFCryptoException("HSM-CMD-SM2 签名,参数错误");
        }
        RequestMessage req = new RequestMessage(CMDCode.SM2_SIGN, buffer.toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-SM2 签名,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-SM2 签名,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * SM2 验证签名 内部公钥 1 | 外部公钥 0
     *
     * @param keyIndex 密钥索引 外部密钥传-1
     * @param pubKey   公钥 内部密钥传null
     * @param data     数据 长度固定为 32 字节 取SM3摘要
     * @param sign     签名
     * @return true | false
     */
    public boolean sm2Verify(int keyIndex, byte[] pubKey, byte[] data, byte[] sign) throws AFCryptoException {
        logger.info("HSM-CMD-SM2 验证签名, keyIndex: {}, pubKey: {}, data: {}, sign: {}", keyIndex, pubKey, data, sign);
        BytesBuffer buffer = new BytesBuffer();
        if (-1 != keyIndex && null == pubKey) { //内部密钥
            buffer.append(1)
                    .append(keyIndex)
                    .append(data.length)   //取SM3摘要
                    .append(data)
                    .append(sign.length)
                    .append(sign);
        } else if (-1 == keyIndex && null != pubKey) { //外部密钥
            buffer.append(0)
                    .append(Algorithm.SGD_SM2_1.getValue())
                    .append(0)

                    .append(pubKey.length)
                    .append(pubKey)

                    .append(data.length)   //取SM3摘要
                    .append(data)
                    .append(sign.length)
                    .append(sign);
        } else {
            throw new AFCryptoException("HSM-CMD-SM2 验证签名,参数错误");
        }
        RequestMessage req = new RequestMessage(CMDCode.SM2_VERIFY, buffer.toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-SM2 验证签名,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-SM2 验证签名,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return true;
    }

    /**
     * SM2 加密 内部公钥 1 | 外部公钥 0
     *
     * @param keyIndex 密钥索引 外部密钥传-1
     * @param pubKey   公钥 内部密钥传null
     * @param plain    明文数据
     * @return 4+n
     */
    public byte[] sm2Encrypt(int keyIndex, byte[] pubKey, byte[] plain) throws AFCryptoException {
        logger.info("HSM-CMD-SM2 加密, keyIndex: {}, pubKey: {}, data: {}", keyIndex, pubKey, plain);
        BytesBuffer buffer = new BytesBuffer();
        if (-1 != keyIndex && null == pubKey) { //内部密钥
            buffer.append(keyIndex)
                    .append(Algorithm.SGD_SM2_3.getValue())
                    .append(0)
                    .append(0)
                    .append(plain.length)   //取SM3摘要
                    .append(plain);
        } else if (-1 == keyIndex && null != pubKey) { //外部密钥
            buffer.append(0)
                    .append(Algorithm.SGD_SM2_3.getValue())
                    .append(0)

                    .append(pubKey.length)
                    .append(pubKey)

                    .append(plain.length)   //取SM3摘要
                    .append(plain);
        } else {
            throw new AFCryptoException("HSM-CMD-SM2 加密,参数错误");
        }
        RequestMessage req = new RequestMessage(CMDCode.SM2_ENCRYPT, buffer.toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-SM2 加密,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-SM2 加密,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * SM2 解密 内部私钥 1 | 外部私钥 0
     *
     * @param keyIndex 密钥索引 外部密钥传-1
     * @param priKey   私钥 内部密钥传null
     * @param cipher   密文数据
     * @return 4+n
     */
    public byte[] sm2Decrypt(int keyIndex, byte[] priKey, byte[] cipher) throws AFCryptoException {
        logger.info("HSM-CMD-SM2 解密, keyIndex: {}, priKey: {}, data: {}", keyIndex, priKey, cipher);
        BytesBuffer buffer = new BytesBuffer();
        if (-1 != keyIndex && null == priKey) { //内部密钥
            buffer.append(keyIndex)
                    .append(Algorithm.SGD_SM2_3.getValue())
                    .append(0)
                    .append(0)
                    .append(cipher.length)   //取SM3摘要
                    .append(cipher);
        } else if (-1 == keyIndex && null != priKey) { //外部密钥
            buffer.append(0)
                    .append(Algorithm.SGD_SM2_3.getValue())
                    .append(0)

                    .append(priKey.length)
                    .append(priKey)

                    .append(cipher.length)   //取SM3摘要
                    .append(cipher);
        } else {
            throw new AFCryptoException("HSM-CMD-SM2 解密,参数错误");
        }
        RequestMessage req = new RequestMessage(CMDCode.SM2_DECRYPT, buffer.toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-SM2 解密,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-SM2 解密,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 对称加密  SM1 SM4
     *
     * @param algorithm 算法 只能是{@link Algorithm}中的SM1,SM4相关枚举
     * @param type      接口标识 0|外部密钥，1|内部密钥，2|检查密钥句柄
     * @param keyIndex  密钥索引 仅在接口标识为 1|2 时有效
     * @param key       密钥
     * @param iv        向量
     * @param plain     数据 分组且padding过的数据
     * @return 加密后的数据
     * <p>
     * 1、4 字节密文数据长度
     * 2、密文数据
     * 3、IV 数据信息（若输入 IV 信息长度不为 0 时有效）
     * </p>
     */
    public byte[] symEncrypt(Algorithm algorithm, int type, int keyIndex, byte[] key, byte[] iv, byte[] plain) throws AFCryptoException {
        logger.info("HSM-CMD-对称加密, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, plainLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, plain.length);
        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(type)
                .append(keyIndex)
                .append(null == key ? 0 : key.length)
                .append(key)
                .append(null == iv ? 0 : iv.length)
                .append(iv)
                .append(plain.length)
                .append(plain)
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_ENCRYPT, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-对称加密失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, plain.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-对称加密失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + plain.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 对称解密  SM1 SM4
     *
     * @param algorithm 算法 只能是{@link Algorithm}中的SM1,SM4相关枚举
     * @param type      接口标识 0|外部密钥，1|内部密钥，2|检查密钥句柄
     * @param keyIndex  密钥索引 仅在接口标识为 1|2 时有效
     * @param key       密钥
     * @param iv        向量
     * @param cipher    加密数据
     * @return 解密后的数据 :
     * <p>1、4字节明文数据长度 </p>
     * <p>2、明文数据</p>
     */
    public byte[] symDecrypt(Algorithm algorithm, int type, int keyIndex, byte[] key, byte[] iv, byte[] cipher) throws AFCryptoException {
        logger.info("HSM-CMD-对称解密, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, cipher.length);

        byte[] param = new BytesBuffer()
                .append(algorithm.getValue())
                .append(type)
                .append(keyIndex)
                .append(null == key ? 0 : key.length)
                .append(key)
                .append(null == iv ? 0 : iv.length)
                .append(iv)
                .append(cipher.length)
                .append(cipher)
                .toBytes();

        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_DECRYPT, param, agKey));
        if (res.getHeader().

                getErrorCode() != 0) {
            logger.error("HSM-CMD-对称解密失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, cipher.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-对称解密失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + cipher.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().

                readOneData();

    }

    /**
     * 对称加密批量  SM1 SM4
     *
     * @param algorithm 算法 只能是{@link Algorithm}中的SM1,SM4相关枚举
     * @param type      接口标识 0|外部密钥，1|内部密钥，2|检查密钥句柄
     * @param keyIndex  密钥索引 仅在接口标识为 1|2 时有效
     * @param key       密钥
     * @param iv        向量
     * @param dataList  数据 分组且padding过的数据
     * @return <p>1、4 字节原始数据个数
     * 2、4 字节加密数据长度
     * 3、加密数据信息 </p>
     */
    public byte[] symEncryptBatch(Algorithm algorithm, int type, int keyIndex, byte[] key, byte[] iv, List<byte[]> dataList) throws AFCryptoException {
        logger.info("HSM-CMD-对称加密批量, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, dataList.size());
        BytesBuffer buffer = new BytesBuffer()
                .append(algorithm.getValue())
                .append(type)
                .append(keyIndex)
                .append(null == key ? 0 : key.length)
                .append(key)
                .append(null == iv ? 0 : iv.length)
                .append(iv)
                .append(dataList.size());
        dataList.forEach(data -> buffer.append(data.length).append(data));
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_ENCRYPT_BATCH, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-对称加密批量失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, dataList.size(), res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-对称加密批量失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + dataList.size() + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }

    /**
     * 对称解密批量  SM1 SM4
     *
     * @param algorithm 算法 只能是{@link Algorithm}中的SM1,SM4相关枚举
     * @param type      接口标识 0|外部密钥，1|内部密钥，2|检查密钥句柄
     * @param keyIndex  密钥索引 仅在接口标识为 1|2 时有效
     * @param key       密钥
     * @param iv        向量
     * @param dataList  数据 分组且padding过的数据
     * @return 解密后的数据
     * <p>1、4 字节原始数据个数
     * 2、4 字节原始数据长度
     * 3、原始数据信息</p>
     */
    public byte[] symDecryptBatch(Algorithm algorithm, int type, int keyIndex, byte[] key, byte[] iv, List<byte[]> dataList) throws AFCryptoException {
        logger.info("HSM-CMD-对称解密批量, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, dataList.size());
        BytesBuffer buffer = new BytesBuffer()
                .append(algorithm.getValue())
                .append(type)
                .append(keyIndex)
                .append(null == key ? 0 : key.length)
                .append(key)
                .append(null == iv ? 0 : iv.length)
                .append(iv)
                .append(dataList.size());
        dataList.forEach(data -> buffer.append(data.length).append(data));
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_DECRYPT_BATCH, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-对称解密批量失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, dataList.size(), res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-对称解密批量失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + dataList.size() + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }

    /**
     * MAC计算 SM1 SM4
     *
     * @param algorithm 算法 {@link Algorithm}  必须为SM1|SM4 CBC 类型算法
     * @param type      接口标识 0|外部密钥，1|内部密钥，2|检查密钥句柄
     * @param keyIndex  密钥索引 仅在接口标识为 1|2 时有效
     * @param key       密钥
     * @param iv        向量
     * @param data      数据
     * @return 4字节长度+MAC值
     */
    public byte[] mac(Algorithm algorithm, int type, int keyIndex, byte[] key, byte[] iv, byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-MAC计算, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, data.length);
        BytesBuffer buffer = new BytesBuffer()
                .append(algorithm.getValue())  //必须为 CBC 类型算法
                .append(type)
                .append(keyIndex)
                .append(null == key ? 0 : key.length)
                .append(key)
                .append(null == iv ? 0 : iv.length)
                .append(iv)
                .append(data.length)
                .append(data);
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_CALCULATEMAC, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-MAC计算失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-MAC计算失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * SM3-HMAC 计算
     *
     * @param key  密钥
     * @param data 数据
     * @return 4字节长度+MAC值
     */
    public byte[] sm3Hmac(byte[] key, byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-SM3 HMAc计算, keyLen:{},  dataLen:{}", key.length, data.length);
        BytesBuffer buffer = new BytesBuffer()
                .append(key.length)
                .append(key)
                .append(data.length)
                .append(data);
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_CALCULATEHASH, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-SM3 HMAc计算失败, keyLen:{},  dataLen:{}, 错误码:{},错误信息:{}", key.length, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-SM3 HMAc计算失败, keyLen:" + key.length + ",  dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * HASH INIT 计算
     *
     * @param algorithm SGD_SM3|SGD_SHA1...等
     * @param publicKey 公钥 仅在算法为 SGD_SM3 时有效
     * @param userId    用户ID
     */
    public void hashInit(Algorithm algorithm, byte[] publicKey, byte[] userId) throws AFCryptoException {
        logger.info("HSM-CMD-HASH INIT, algorithm:{}, publicKeyLen:{},  userIdLen:{}", algorithm, null == publicKey ? 0 : publicKey.length, null == userId ? 0 : userId.length);
        BytesBuffer buffer = new BytesBuffer()
                .append(algorithm.getValue())
                .append(null == publicKey ? 0 : publicKey.length)  // 仅在算法为 SGD_SM3 时有效
                .append(publicKey)        //仅在算法为 SGD_SM3 时有效
                .append(null == userId ? 0 : userId.length)
                .append(userId);
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_HASHINIT, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-HASH INIT失败, algorithm:{}, publicKeyLen:{},  userIdLen:{}, 错误码:{},错误信息:{}", algorithm, null == publicKey ? 0 : publicKey.length, null == userId ? 0 : userId.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-HASH INIT失败, algorithm:" + algorithm + ", publicKeyLen:" + (null == publicKey ? 0 : publicKey.length) + ",  userIdLen:" + (null == userId ? 0 : userId.length) + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
    }

    /**
     * HASH UPDATE 计算
     *
     * @param data 数据
     */
    public void hashUpdate(byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-HASH UPDATE, dataLen:{}", data.length);
        BytesBuffer buffer = new BytesBuffer()
                .append(data.length)
                .append(data);
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_HASHUPDATE, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-HASH UPDATE失败, dataLen:{}, 错误码:{},错误信息:{}", data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-HASH UPDATE失败, dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        logger.info("HSM-CMD-HASH UPDATE成功");
    }

    /**
     * HASH FINAL 计算
     *
     * @return HASH值 4+N
     */
    public byte[] hashFinal() throws AFCryptoException {
        logger.info("HSM-CMD-HASH FINAL");
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_HASHFINAL, null, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-HASH FINAL失败, 错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-HASH FINAL失败, 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 创建文件操作
     *
     * @param fileName 文件名
     * @param dataLen  文件长度
     */
    public void createFile(String fileName, int dataLen) throws AFCryptoException {
        logger.info("HSM-CMD-创建文件, fileName:{}, dataLen:{}", fileName, dataLen);
        byte[] param = new BytesBuffer()
                .append(dataLen)
                .append(0)
                .append(fileName.length())
                .append(fileName.getBytes())
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_CREATEFILE, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-创建文件失败, fileName:{}, dataLen:{}, 错误码:{},错误信息:{}", fileName, dataLen, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-创建文件失败, fileName:" + fileName + ", dataLen:" + dataLen + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        logger.info("HSM-CMD-创建文件成功");
    }

    /**
     * 读取文件操作
     *
     * @param fileName 文件名
     * @param offset   偏移量
     * @param len      读取长度
     * @return 文件内容 4+N
     */
    public byte[] readFile(String fileName, int offset, int len) throws AFCryptoException {
        logger.info("HSM-CMD-读取文件, fileName:{}, offset:{}, len:{}", fileName, offset, len);
        byte[] param = new BytesBuffer()
                .append(offset)
                .append(len)
                .append(fileName.length())
                .append(fileName.getBytes())
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_READFILE, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-读取文件失败, fileName:{}, offset:{}, len:{}, 错误码:{},错误信息:{}", fileName, offset, len, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-读取文件失败, fileName:" + fileName + ", offset:" + offset + ", len:" + len + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 写文件操作
     *
     * @param fileName 文件名
     * @param offset   偏移量
     * @param data     写入数据
     */
    public void writeFile(String fileName, int offset, byte[] data) throws AFCryptoException {
        logger.info("HSM-CMD-写文件, fileName:{}, offset:{}, dataLen:{}", fileName, offset, data.length);
        byte[] param = new BytesBuffer()
                .append(offset)
                .append(fileName.length())
                .append(fileName.getBytes())
                .append(data.length)
                .append(data)
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_WRITEFILE, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-写文件失败, fileName:{}, offset:{}, dataLen:{}, 错误码:{},错误信息:{}", fileName, offset, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-写文件失败, fileName:" + fileName + ", offset:" + offset + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        logger.info("HSM-CMD-写文件成功");
    }

    /**
     * 删除文件操作
     *
     * @param fileName 文件名
     */
    public void deleteFile(String fileName) throws AFCryptoException {
        logger.info("HSM-CMD-删除文件, fileName:{}", fileName);
        byte[] param = new BytesBuffer()
                .append(fileName.length())
                .append(fileName.getBytes())
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_DELETEFILE, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-删除文件失败, fileName:{}, 错误码:{},错误信息:{}", fileName, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-删除文件失败, fileName:" + fileName + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        logger.info("HSM-CMD-删除文件成功");
    }

    /**
     * 获取内部对称密钥句柄
     *
     * @param keyIndex 密钥索引
     * @return 密钥句柄
     */
    public int getSymKeyHandle(int keyIndex) throws AFCryptoException {
        logger.info("HSM-CMD-获取内部对称密钥句柄, keyIndex:{}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_GETSYMKEYHANDLE, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-CMD-获取内部对称密钥句柄失败, keyIndex:{}, 错误码:{},错误信息:{}", keyIndex, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-CMD-获取内部对称密钥句柄失败, keyIndex:" + keyIndex + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readInt();
    }

    /**
     * 获取私钥访问权限
     *
     * @param index   私钥索引
     * @param keyType 密钥类型 3|SM2，4|RSA
     */
    public void getPrivateAccess(int index, int keyType, String pwd) throws AFCryptoException {
        byte[] param = new BytesBuffer()
                .append(index)
                .append(keyType)
                .append(pwd.length())
                .append(pwd.getBytes(StandardCharsets.UTF_8))
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GETPRIVATEKEYACCESSRIGHT, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("获取私钥访问权限失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("获取私钥访问权限失败");
        }
    }

    //===========================================工具方法===========================================

    private static byte[] getBytes(byte[] bytesResponse, int offset, int length) {
        return BytesOperate.subBytes(bytesResponse, offset, length);
    }


}