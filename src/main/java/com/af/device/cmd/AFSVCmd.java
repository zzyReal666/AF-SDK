package com.af.device.cmd;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.Algorithm;
import com.af.constant.CMDCode;
import com.af.constant.ConstantNumber;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.device.DeviceInfo;
import com.af.exception.AFCryptoException;
import com.af.netty.NettyClient;
import com.af.nettyNew.NettyClientChannels;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.signAndVerify.AFSM2DecodeSignedData;
import com.af.struct.signAndVerify.AFSvCryptoInstance;
import com.af.struct.signAndVerify.CertAltNameTrustList;
import com.af.struct.signAndVerify.CertList;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;
import lombok.Setter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.util.List;
import java.util.Locale;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/19 12:02
 */
@ToString
public class AFSVCmd {

    //region// 成员变量
    private static final Logger logger = LoggerFactory.getLogger(AFSVCmd.class);
    private final NettyClient client;
    @Setter
    private byte[] agKey;

    public AFSVCmd(NettyClient client, byte[] agKey) {
        this.client = client;
        this.agKey = agKey;
    }
    //endregion

    //region// 导出公钥

    /**
     * 导出RSA公钥 签名公钥/加密公钥
     * <p>导出RSA公钥</p>
     * <p>导出密码机内部对应索引和用途的RSA公钥信息</p>
     *
     * @param keyIndex ：密码设备内部存储的RSA索引号
     * @param keyUsage ：密钥用途，0：签名公钥；1：加密公钥
     * @return : 返回Base64编码的公钥数据
     */
    public byte[] getRSAPublicKey(int keyIndex, int keyUsage) throws AFCryptoException { //success
        logger.info("SV-导出RSA公钥, keyIndex:{}, keyUsage:{}", keyIndex, keyUsage);
        //参数校验
        if (keyIndex < 0 || keyIndex > 1023) {
            logger.error("SV-导出RSA公钥失败, keyIndex:{} 超出范围(0-1023)", keyIndex);
            throw new AFCryptoException("SV-导出RSA公钥失败, keyIndex:" + keyIndex + " 超出范围(0-1023)");
        }
        int type;
        int cmdID;
        // 导出签名公钥
        if (ConstantNumber.SIGN_PUBLIC_KEY == keyUsage) {
            type = ConstantNumber.SGD_RSA_SIGN;
            cmdID = CMDCode.CMD_EXPORTSIGNPUBLICKEY_RSA;
        }
        // 导出加密公钥
        else if (ConstantNumber.ENC_PUBLIC_KEY == keyUsage) {
            type = ConstantNumber.SGD_RSA_ENC;
            cmdID = CMDCode.CMD_EXPORTENCPUBLICKEY_RSA;
        }
        //非法参数
        else {
            logger.error("SV-导出RSA公钥失败, keyUsage:{} 不合法(0:签名公钥; 1:加密公钥)", keyUsage);
            throw new AFCryptoException("SV-导出RSA公钥失败, keyUsage:" + keyUsage + " 不合法(0:签名公钥; 1:加密公钥)");
        }
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(type)
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(cmdID, param, agKey);
        ResponseMessage responseMessage = client.send(requestMessage);
        if (responseMessage.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出RSA公钥失败, 错误码:{}, 错误信息:{}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出RSA公钥失败, 错误码:" + responseMessage.getHeader().getErrorCode() + ", 错误信息:" + responseMessage.getHeader().getErrorInfo());
        }
        return responseMessage.getDataBuffer().readOneData();
    }


    /**
     * 导出SM2加密公钥
     *
     * @param keyIndex 密钥索引
     */
    public byte[] getSM2EncPublicKey(int keyIndex) throws AFCryptoException {  //success
        logger.info("SV-导出SM2加密公钥,keyIndex:{}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_2)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTENCPUBLICKEY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出SM2加密公钥错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出SM2加密公钥错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 导出SM2签名公钥
     *
     * @param keyIndex 密钥索引
     */
    public byte[] getSM2SignPublicKey(int keyIndex) throws AFCryptoException {  //success
        logger.info("SV-导出SM2签名公钥,keyIndex:{}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .append(ConstantNumber.SGD_SM2_1)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTSIGNPUBLICKEY_ECC, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出SM2签名公钥错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出SM2签名公钥错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    //endregion

    //region// 设备信息 随机数 获取私钥访问权限

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * 获取设备信息异常
     */
    public DeviceInfo getDeviceInfo() throws AFCryptoException {  //success
        logger.info("SV-获取设备信息");
        RequestMessage req = new RequestMessage(CMDCode.CMD_DEVICEINFO, null, agKey);
        //发送请求
        ResponseMessage resp = client.send(req);
        if (resp.getHeader().getErrorCode() != 0) {
            logger.error("获取设备信息错误,无响应或者响应码错误,错误码:{},错误信息:{}", resp.getHeader().getErrorCode(), resp.getHeader().getErrorInfo());
            throw new AFCryptoException("获取设备信息错误");
        }
        //解析响应
        DeviceInfo info = new DeviceInfo();
        info.decode(resp.getDataBuffer().readOneData());
        return info;
    }

    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * 获取随机数异常
     */
    public byte[] getRandom(int length) throws AFCryptoException {  //success
        logger.info("SV-获取随机数, length:{}", length);
        byte[] param = new BytesBuffer().append(length).toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATERANDOM, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取随机数失败, 错误码:{}, 错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取随机数失败, 错误码:" + res.getHeader().getErrorCode() + ", 错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 获取私钥访问权限
     *
     * @param index   索引
     * @param keyType 密钥类型 3:SM2 4:RSA
     */
    public void getPrivateAccess(int index, int keyType) throws AFCryptoException { //success
        logger.info("SV-CMD 获取私钥访问权限, index: {}, keyType: {}", index, keyType);
        String pwd = "12345678";
        byte[] param = new BytesBuffer()
                .append(index)
                .append(keyType)
                .append(pwd.length())
                .append(pwd.getBytes(StandardCharsets.UTF_8))
                .toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_GETPRIVATEKEYACCESSRIGHT, param, agKey);
        int count = client instanceof NettyClientChannels ? ((NettyClientChannels) client).getNettyChannelPool().getChannelCount() : 1;
        for (int i = 0; i < count; i++) {
            ResponseMessage responseMessage = client.send(requestMessage);
            if (responseMessage.getHeader().getErrorCode() != 0) {
                logger.error("获取私钥访问权限失败, 错误码: {}, 错误信息: {}", responseMessage.getHeader().getErrorCode(), responseMessage.getHeader().getErrorInfo());
                throw new AFCryptoException("获取私钥访问权限失败");
            }
        }

    }
    //endregion

    //region//导出公钥 生成密钥对 释放密钥信息

    /**
     * 导出公钥信息
     *
     * @param index     密钥索引
     * @param algorithm 算法标识
     */
    public byte[] exportPublicKey(int index, Algorithm algorithm) throws AFCryptoException {
        logger.info("SV-导出公钥信息, index: {}, keyType: {}", index, algorithm);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(algorithm.getValue())
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.EXPORT_PUBLIC_KEY, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-导出公钥信息,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-导出公钥信息,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
     * 释放密钥信息
     *
     * @param keyIndex 密钥索引
     */
    public void freeKey(int keyIndex) throws AFCryptoException {
        logger.info("SV-释放密钥信息, keyIndex: {}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_DESTROYKEY, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-释放密钥信息,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-释放密钥信息,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
    }
    //endregion

    //region// RSA 通讯

    /**
     * RSA 公钥操作 加密|验签
     *
     * @param keyIndex  密钥索引 外部密钥传0
     * @param pubKey    公钥    内部密钥传null
     * @param algorithm 算法标识  SGD_RSA_ENC|SGD_RSA_SIGN
     * @param data      数据
     */
    public byte[] rsaPublicKeyOperation(int keyIndex, RSAPubKey pubKey, Algorithm algorithm, byte[] data) throws AFCryptoException {
        logger.info("SV-RSA 公钥操作, keyIndex: {}, pubKey: {}, keyType: {}, data: {}", keyIndex, pubKey, algorithm, data);
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
            logger.error("SV-RSA 公钥操作,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA 公钥操作,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * RSA 私钥操作 签名|解密
     *
     * @param keyIndex  密钥索引 外部密钥传0
     * @param priKey    私钥    内部密钥传null
     * @param algorithm 算法标识 SGD_RSA_ENC|SGD_RSA_SIGN
     * @param data      数据
     */
    public byte[] rsaPrivateKeyOperation(int keyIndex, RSAPriKey priKey, Algorithm algorithm, byte[] data) throws AFCryptoException {
        logger.info("SV-RSA 私钥操作, keyIndex: {}, priKey: {}, keyType: {}, data: {}", keyIndex, null == priKey ? "" : priKey, algorithm, data);
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
            logger.error("SV-RSA 私钥操作,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-RSA 私钥操作,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }
    //endregion

    // region// SM2 通讯

    /**
     * SM2 签名 内部私钥 1 | 外部私钥 0
     *
     * @param keyIndex 密钥索引 外部密钥传-1
     * @param priKey   私钥 内部密钥传null
     * @param data     数据 长度固定为 32 字节 取SM3摘要
     * @return 4+n
     */
    public byte[] sm2Sign(int keyIndex, byte[] priKey, byte[] data) throws AFCryptoException {
        logger.info("SV-CMD-SM2 签名, keyIndex: {}, priKey: {}, data: {}", keyIndex, null == priKey, data);
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
            throw new AFCryptoException("SV-CMD-SM2 签名,参数错误");
        }
        RequestMessage req = new RequestMessage(CMDCode.SM2_SIGN, buffer.toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-SM2 签名,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-SM2 签名,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
        logger.info("SV-CMD-SM2 验证签名, keyIndex: {}, pubKey: {}, data: {}, sign: {}", keyIndex, pubKey, data, sign);
        BytesBuffer buffer = new BytesBuffer();
        if (-1 != keyIndex && null == pubKey) { //内部密钥
            buffer.append(1)
                    .append(keyIndex)
                    .append(data.length)
                    .append(data)
                    .append(sign.length)
                    .append(sign);
        } else if (-1 == keyIndex && null != pubKey) { //外部密钥
            buffer.append(0)
                    .append(Algorithm.SGD_SM2_1.getValue())
                    .append(0)

                    .append(pubKey.length)
                    .append(pubKey)

                    .append(data.length)
                    .append(data)
                    .append(sign.length)
                    .append(sign);
        } else {
            throw new AFCryptoException("SV-CMD-SM2 验证签名,参数错误");
        }
        RequestMessage req = new RequestMessage(CMDCode.SM2_VERIFY, buffer.toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-SM2 验证签名,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-SM2 验证签名,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
        logger.info("SV-CMD-SM2 加密, keyIndex: {}, pubKey: {}, data: {}", keyIndex, pubKey, plain);
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
            throw new AFCryptoException("SV-CMD-SM2 加密,参数错误");
        }
        RequestMessage req = new RequestMessage(CMDCode.SM2_ENCRYPT, buffer.toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-SM2 加密,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-SM2 加密,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
        logger.info("SV-CMD-SM2 解密, keyIndex: {}, priKey: {}, data: {}", keyIndex, priKey, cipher);
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
            throw new AFCryptoException("SV-CMD-SM2 解密,参数错误");
        }
        RequestMessage req = new RequestMessage(CMDCode.SM2_DECRYPT, buffer.toBytes(), agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-SM2 解密,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-SM2 解密,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }
    //endregion

    //region// 对称加密通讯

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
        logger.info("SV-CMD-对称加密, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, plainLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, plain.length);
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
            logger.error("SV-CMD-对称加密失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, plain.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-对称加密失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + plain.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
        logger.info("SV-CMD-对称解密, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, cipher.length);
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
            logger.error("SV-CMD-对称解密失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, cipher.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-对称解密失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + cipher.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
        logger.info("SV-对称加密批量, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, dataList.size());
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
            logger.error("SV-对称加密批量失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, dataList.size(), res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-对称加密批量失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + dataList.size() + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
        logger.info("SV-对称解密批量, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, dataList.size());
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
            logger.error("SV-对称解密批量失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, dataList.size(), res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-对称解密批量失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + dataList.size() + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }
    //endregion

    //region//  MAC HMAC Hash通讯

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
        logger.info("SV-CMD-MAC计算, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, data.length);
        if (data.length > 2 * 1024 * 1024) {
            logger.error("SV-CMD-MAC计算，计算数据长度不能超过2M,当前长度：{}", data.length);
            throw new AFCryptoException("SV-CMD-MAC计算，计算数据长度不能超过2M,当前长度：" + data.length);
        }
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
            logger.error("SV-CMD-MAC计算失败, algorithm:{}, type:{}, keyIndex:{}, keyLen:{}, ivLen:{}, dataLen:{}, 错误码:{},错误信息:{}", algorithm, type, keyIndex, null == key ? 0 : key.length, null == iv ? 0 : iv.length, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-MAC计算失败, algorithm:" + algorithm + ", type:" + type + ", keyIndex:" + keyIndex + ", keyLen:" + (null == key ? 0 : key.length) + ", ivLen:" + (null == iv ? 0 : iv.length) + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
        logger.info("SV-CMD-SM3 HMAc计算, keyLen:{},  dataLen:{}", key.length, data.length);
        //data 不能超过2M
        if (data.length > 2 * 1024 * 1024) {
            logger.error("SV-CMD-SM3 HMAc计算，计算数据长度不能超过2M,当前长度：{}", data.length);
            throw new AFCryptoException("SV-CMD-SM3 HMAc计算，计算数据长度不能超过2M,当前长度：" + data.length);
        }
        BytesBuffer buffer = new BytesBuffer()
                .append(key.length)
                .append(key)
                .append(data.length)
                .append(data);
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_CALCULATEHASH, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-SM3 HMAc计算失败, keyLen:{},  dataLen:{}, 错误码:{},错误信息:{}", key.length, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-SM3 HMAc计算失败, keyLen:" + key.length + ",  dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
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
        logger.info("SV-CMD-HASH INIT, algorithm:{}, publicKeyLen:{},  userIdLen:{}", algorithm, null == publicKey ? 0 : publicKey.length, null == userId ? 0 : userId.length);
        BytesBuffer buffer = new BytesBuffer()
                .append(algorithm.getValue())
                .append(null == publicKey ? 0 : publicKey.length)  // 仅在算法为 SGD_SM3 时有效
                .append(publicKey)        //仅在算法为 SGD_SM3 时有效
                .append(null == userId ? 0 : userId.length)
                .append(userId);
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_HASHINIT, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-HASH INIT失败, algorithm:{}, publicKeyLen:{},  userIdLen:{}, 错误码:{},错误信息:{}", algorithm, null == publicKey ? 0 : publicKey.length, null == userId ? 0 : userId.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-HASH INIT失败, algorithm:" + algorithm + ", publicKeyLen:" + (null == publicKey ? 0 : publicKey.length) + ",  userIdLen:" + (null == userId ? 0 : userId.length) + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
    }

    /**
     * HASH UPDATE 计算
     *
     * @param data 数据
     */
    public void hashUpdate(byte[] data) throws AFCryptoException {
        logger.info("SV-CMD-HASH UPDATE, dataLen:{}", data.length);
        BytesBuffer buffer = new BytesBuffer()
                .append(data.length)
                .append(data);
        byte[] param = buffer.toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_HASHUPDATE, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-HASH UPDATE失败, dataLen:{}, 错误码:{},错误信息:{}", data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-HASH UPDATE失败, dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        logger.info("SV-CMD-HASH UPDATE成功");
    }

    /**
     * HASH FINAL 计算
     *
     * @return HASH值 4+N
     */
    public byte[] hashFinal() throws AFCryptoException {
        logger.info("SV-CMD-HASH FINAL");
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_HASHFINAL, null, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-HASH FINAL失败, 错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-HASH FINAL失败, 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    //endregion

    //region// 获取内部对称密钥句柄

    /**
     * 获取内部对称密钥句柄
     *
     * @param keyIndex 密钥索引
     * @return 密钥句柄
     */
    public int getSymKeyHandle(int keyIndex) throws AFCryptoException {
        logger.info("SV-CMD-获取内部对称密钥句柄, keyIndex:{}", keyIndex);
        byte[] param = new BytesBuffer()
                .append(keyIndex)
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_GETSYMKEYHANDLE, param, agKey));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-CMD-获取内部对称密钥句柄失败, keyIndex:{}, 错误码:{},错误信息:{}", keyIndex, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-CMD-获取内部对称密钥句柄失败, keyIndex:" + keyIndex + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readInt();
    }
    //endregion

    //region// 证书管理

    /**
     * 根据别名获取 CA 证书个数<br>
     * 根据别名获取 CA 证书
     *
     * @param subCmd  0x01：获取证书个数；0x02：获取证书
     * @param index   证书索引
     * @param altName 证书别名
     * @return 证书列表
     */
    public CertList getCertListByAltName(int subCmd, int index, byte[] altName) throws AFCryptoException { //success
        logger.info("SV-根据证书别名获取信任证书信息, subCmd:{}, index:{}, altName:{}", subCmd, index, new String(altName));
        BytesBuffer buffer = new BytesBuffer()
                .append(subCmd);
        if (subCmd == 0x02) {
            buffer.append(index);
        }
        byte[] param = buffer
                .append(altName.length)
                .append(altName)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-根据证书别名获取信任证书的个数错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-根据证书别名获取信任证书的个数错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();
        CertList list = new CertList();
        if (subCmd == 0x01) {
            list.setCertCount(BytesOperate.bytes2int(getBytes(responseData, 0, 4)));
        } else {
            list.setCertData(res.getDataBuffer().readOneData());
        }
        return list;
    }

    /**
     * 获取所有 CA 证书的别名
     */
    public CertAltNameTrustList getCertTrustListAltName() throws AFCryptoException {  //success
        logger.info("SV-查询证书信任列表别名");
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_ALL_ALT_NAME, null, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-查询证书信任列表别名错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-查询证书信任列表别名错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();
        int nameNumber = BytesOperate.bytes2int(getBytes(responseData, 0, 4));
        int certListLen = BytesOperate.bytes2int(getBytes(responseData, 4, 4));
        byte[] certList = getBytes(responseData, 4 + 4, certListLen);
//        byte[] certList = res.getDataBuffer().readOneData();
        return new CertAltNameTrustList(certList, nameNumber);
    }


    /**
     * 验证证书一
     *
     * <p>验证证书有效性，通过OCSP模式获取当前证书的有效性。 注：选择此方式验证证书有效性，需连接互联网，或者可以访问到待测证书的OCSP服务器</p>
     *
     * @param base64Certificate : 待验证的证书--BASE64编码格式
     * @return ：返回证书验证结果，0为验证通过
     */
    public int validateCertificate(byte[] base64Certificate) throws AFCryptoException { //success
        logger.info("SV-OCSP验证证书有效性, base64Certificate:{}", base64Certificate);
        byte[] param = new BytesBuffer()
                .append(base64Certificate.length)
                .append(base64Certificate)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_VERIFY_CERT, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.info("SV-OCSP验证证书有效性错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
        }
        return res.getHeader().getErrorCode();
    }


    /**
     * 验证证书二
     * <p>验证证书是否被吊销，通过CRL模式获取当前证书的有效性。</p>
     *
     * @param base64Certificate 待验证的证书--BASE64编码格式
     * @param crlData           待验证证书的CRL文件数据 --BASE64编码格式
     * @return ：返回证书验证结果，true ：当前证书已被吊销, false ：当前证书未被吊销
     */
    public boolean isCertificateRevoked(byte[] base64Certificate, byte[] crlData) throws CertificateException, AFCryptoException { //success
        logger.info("SV-验证证书是否被吊销, base64CertificateLen:{}, crlData:{}", base64Certificate.length, crlData);
        ByteArrayInputStream inputCertificate = new ByteArrayInputStream(BytesOperate.base64DecodeCert(new String(base64Certificate)));
        CertificateFactory certCf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Cert = (X509Certificate) certCf.generateCertificate(inputCertificate);
        ByteArrayInputStream inputCrl = new ByteArrayInputStream(BytesOperate.base64DecodeCRL(new String(crlData)));
        CertificateFactory crlCf = CertificateFactory.getInstance("X.509");
        X509CRL x509Crl;
        try {
            x509Crl = (X509CRL) crlCf.generateCRL(inputCrl);
        } catch (CRLException e) {
            logger.error("SV-验证证书是否被吊销失败, 错误信息:{}", e.getMessage());
            throw new AFCryptoException(e.getMessage());
        }
        return x509Crl.isRevoked(x509Cert);

    }

    /**
     * 获取证书信息
     *
     * @param base64Certificate ：Base64编码的证书文件
     * @param certInfoType      : 用户待获取的证书内容类型 : 类型定义在类{@link com.af.constant.CertParseInfoType}
     * @return ：用户获取到的证书信息内容
     */
    public byte[] getCertInfo(byte[] base64Certificate, int certInfoType) throws AFCryptoException { //success
        logger.info("SV-获取证书信息,base64CertificateLen:{},certInfoType:{}", base64Certificate.length, certInfoType);
        byte[] param = new BytesBuffer()
                .append(certInfoType)
                .append(base64Certificate.length)
                .append(base64Certificate)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_INFO, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取证书信息错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取证书信息错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] bytes = res.getDataBuffer().readOneData();
        return new String(bytes).toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);

    }

    /**
     * 根据 OID 获取证书信息
     *
     * @param certData ：Base64编码的证书文件
     * @param oid      : 用户待获取的证书内容类型OID值 : OID值定义在类 certParseInfoType 中
     * @return ：用户获取到的证书信息内容
     */
    public byte[] getCertInfoByOid(byte[] certData, byte[] oid) throws AFCryptoException { //success
        logger.info("SV-获取证书扩展信息,certDataLen:{},oid:{}", certData.length, new String(oid));
        byte[] param = new BytesBuffer()
                .append(0)
                .append(oid.length)
                .append(oid)
                .append(certData.length)
                .append(certData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_EXT_TYPE_INFO, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取证书扩展信息错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取证书扩展信息错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();

    }


    /**
     * 获取设备证书
     *
     * @param usage ：证书用途 2|签名证书 ; 3|加密证书
     * @return ：Base64编码的证书
     */
    public byte[] getServerCertByUsage(int usage) throws AFCryptoException { //success
        logger.info("SV-获取设备证书,usage(2|签名证书 ; 3|加密证书):{}", usage);
        byte[] param = new BytesBuffer()
                .append(usage)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_SERVER_CERT_INFO, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取服务器证书错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取服务器证书错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * 获取应用实体信息
     * <p>获取应用策略</p>
     * <p>根据策略名称获取应用策略，此应用策略为用户在管理程序中创建。用户获取应用策略后，签名服务器会根据用户设定的策略内容进行相关的服务操作</p>
     *
     * @param policyName ：策略名称
     */

    public AFSvCryptoInstance getInstance(byte[] policyName) throws AFCryptoException {
        logger.info("SV-获取应用实体信息,policyName:{}", new String(policyName));
        byte[] param = new BytesBuffer()
                .append(policyName.length)
                .append(policyName)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_INSTANCE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-获取应用实体信息,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-获取应用实体信息,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();
        AFSvCryptoInstance instance = new AFSvCryptoInstance();

        //todo  在实体里面decode
        instance.setPolicyName(new String(policyName));
        instance.setKeyIndex(BytesOperate.bytes2int(getBytes(responseData, 0, 4)));
        instance.setKeyType(BytesOperate.bytes2int(getBytes(responseData, 4, 4)));
        instance.setPolicy(BytesOperate.bytes2int(getBytes(responseData, 4 + 4, 4)));

        return instance;

    }

    /**
     * 根据证书的 DN 信息获取 CA 证书
     *
     * @param dn ：证书的 DN 信息 颁发者用户信息
     * @return ：DER编码的证书  4+n
     */
    public byte[] getCaCertByDn(byte[] dn) throws AFCryptoException {
        logger.info("SV-根据证书的 DN 信息获取 CA 证书,dn:{}", dn);
        byte[] param = new BytesBuffer()
                .append(dn.length)
                .append(dn)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CA_CERT_BY_DN, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-根据证书的 DN 信息获取 CA 证书错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-根据证书的 DN 信息获取 CA 证书错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }


    /**
     * 获取应用实体证书数据
     * <p>根据策略名称，获取相应的证书</p>
     *
     * @param policyName : 策略名称
     * @param certType   : 证书类型 1|加密证书; 2|签名证书
     * @return : Base64编码的证书
     */
    public byte[] getCertByPolicyName(byte[] policyName, int certType) throws AFCryptoException { //success
        logger.info("SV-根据策略名称(应用实体)，获取相应的证书,policyName:{},certType(1|加密证书; 2|签名证书):{}", policyName, certType);
        byte[] param = new BytesBuffer()
                .append(policyName.length)
                .append(policyName)
                .append(certType)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CERT_BY_POLICY_NAME, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-根据策略名称，获取相应的证书错误,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-根据策略名称，获取相应的证书错误,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }
    //endregion

    //region// PKCS7 编解码

    /**
     * PKCS7 签名信息编码
     * <p>编码签名数据</p>
     * <p>编码基于SM2算法的签名数据</p>
     *
     * @param keyType    ：消息签名格式，1|带原文，0|不带原文
     * @param privateKey ：base64编码的SM2私钥数据, 其结构应满足 GM/T 0009-2012中关于SM2私钥结构的数据定义
     *                   <p>SM2PrivateKey ::= INTEGER</p>
     * @param certData   ：Base64编码的签名者证书
     * @param data       ：需要签名的数据
     * @return ：Base64编码的签名数据
     */
    public byte[] encodeSignedDataForSM2(int keyType, SM2PrivateKey privateKey, byte[] certData, byte[] data) throws AFCryptoException { //success
        logger.info("SV-编码签名数据, keyType(1|带原文，0|不带原文): {}, signerCertificate: {}, data: {}", keyType, certData, data);
        byte[] param = new BytesBuffer()
                .append(keyType)
                .append(privateKey.encode())
                .append(0)
                .append(certData.length)
                .append(certData)
                .append(ConstantNumber.SGD_SM3)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_SM2_SIGNDATA_ENCODE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-编码签名数据,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-编码签名数据,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

     /**
     * PKCS7 签名信息解码
     * <p>解码签名数据</p>
     * <p>解码基于SM2算法的签名数据</p>
     *
     * @param signedData ：Base64编码的签名数据，其格式应符合GM/T 0010《SM2密码算法加密签名消息语法规范》中SignedData的数据类型定义
     * @return ：解码后的数据，包括签名者证书，HASH算法标识，被签名的数据以及签名值
     */
    public AFSM2DecodeSignedData decodeSignedDataForSM2(byte[] signedData) throws AFCryptoException { //success
        logger.info("SV-解码签名数据, signedData: {}", signedData);
        byte[] param = new BytesBuffer()
                .append(signedData.length)
                .append(signedData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_SM2_SIGNDATA_DECODE, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-解码签名数据,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-解码签名数据,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] responseData = res.getData();

        //签名证书长度
        int certLen = BytesOperate.bytes2int(responseData);
        //签名证书
        byte[] certData = getBytes(responseData, 4, certLen);
        //HASH算法标识
        int hashAlgID = BytesOperate.bytes2int(responseData, 4 + certLen);
        //原文数据长度
        int rawDataLen = BytesOperate.bytes2int(responseData, 4 + certLen + 4);
        //原文数据
        byte[] rawData = getBytes(responseData, 4 + certLen + 4 + 4, rawDataLen);
        //签名数据长度
        int signDataLen = BytesOperate.bytes2int(responseData, 4 + certLen + 4 + 4 + rawDataLen);
        //签名数据
        byte[] result = getBytes(responseData, 4 + certLen + 4 + 4 + rawDataLen + 4, signDataLen);

        return new AFSM2DecodeSignedData(rawData, BytesOperate.base64EncodeCert(certData), hashAlgID, BytesOperate.base64EncodeData(result));
    }

    /**
     * PKCS7 签名信息验证
     * <p>验证签名数据</p>
     *
     * @param rawData  原文数据
     * @param signData 签名数据
     */
    public boolean verifySignedDataForSM2(byte[] rawData, byte[] signData) throws AFCryptoException { //success
        logger.info("SV-验证签名数据, rawData: {}, signData: {}", rawData, signData);
        int rawDataLen = null == rawData ? 0 : rawData.length;
        BytesBuffer buffer = new BytesBuffer()
                .append(signData.length)
                .append(signData)
                .append(rawDataLen);
        if (rawDataLen > 0) {
            buffer.append(rawData);
        }
        byte[] param = buffer.toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_SM2_SIGNDATA_VERIFY, param, agKey);
        ResponseMessage res = client.send(req);
        return res.getHeader().getErrorCode() == 0;

    }

    /**
     * PKCS7 带签名信息的数字信封编码
     * <p>编码数字信封</p>
     * <p>编码基于SM2算法的数字信封</p>
     *
     * @param privateKey:私钥数据
     * @param symmetricKey:对称密钥数据
     * @param signCert            :签名证书
     * @param encryptCert         :加密证书
     * @param data                :原文数据
     * @return :编码后的数字信封数据
     */
    public byte[] encodeEnvelopedDataForSM2(byte[] privateKey, byte[] symmetricKey, byte[] signCert, byte[] encryptCert, byte[] data) throws AFCryptoException { //success
        logger.info("SV-编码数字信封, privateKey: {}, symmetricKey: {}, signCert: {}, encryptCert: {}, dataLen: {}", privateKey, symmetricKey, signCert, encryptCert, data.length);
        byte[] param = new BytesBuffer()
                .append(privateKey.length)
                .append(privateKey)
                .append(symmetricKey.length)
                .append(symmetricKey)
                .append(0)
                .append(signCert.length)
                .append(signCert)
                .append(ConstantNumber.SGD_SM3)
                .append(encryptCert.length)
                .append(encryptCert)
                .append(0)
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.PKCS7_ENCODE_WITH_SIGN, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-编码数字信封,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-编码数字信封,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * PKCS7 带签名信息的数字信封解码
     *
     * @param privateKey:私钥数据
     * @param encodeData      :编码后的数字信封数据
     */
    public byte[] decodeEnvelopedDataForSM2(byte[] privateKey, byte[] encodeData) throws AFCryptoException { //success
        logger.info("SV-解码数字信封, privateKey: {}, encodeData: {}", privateKey, encodeData);
        byte[] param = new BytesBuffer()
                .append(privateKey.length)
                .append(privateKey)
                .append(encodeData.length)
                .append(encodeData)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.PKCS7_DECODE_WITH_SIGN, param, agKey);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("SV-解码数字信封,错误码:{},错误信息:{}", res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("SV-解码数字信封,错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getData();
    }

    //endregion

    //region//工具
    private static byte[] getBytes(byte[] bytesResponse, int offset, int length) {
        return BytesOperate.subBytes(bytesResponse, offset, length);
    }
    //endregion

}
