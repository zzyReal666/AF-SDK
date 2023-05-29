package com.af.device.cmd;

import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.constant.ConstantNumber;
import com.af.constant.GroupMode;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.device.DeviceInfo;
import com.af.device.IAFHsmDevice;
import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.impl.sm2.SM2Cipher;
import com.af.struct.impl.sm2.SM2Signature;
import com.af.utils.BytesBuffer;
import com.af.utils.BytesOperate;

import java.util.Arrays;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/29 11:13
 */
public class AFHSMCmd extends AFCmd {

    public AFHSMCmd(AFNettyClient client, byte[] agKey) {
        super(client, agKey);
    }


    /**
     * 获取设备信息
     *
     * @return 设备信息
     * @throws AFCryptoException 获取设备信息异常
     */

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

    public byte[] getRandom(int length) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM1内部密钥加密
     *
     * @param mode  分组模式 ECB/CBC
     * @param index 内部密钥索引
     * @param iv    初始向量  CBC模式下需要 ECB模式下传null
     * @param data  待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */

    public byte[] sm1Encrypt(GroupMode mode, int index, byte[] iv, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM1内部密钥解密
     *
     * @param mode       分组模式 ECB/CBC
     * @param index      内部密钥索引
     * @param iv         初始向量  CBC模式下需要 ECB模式下传null
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */

    public byte[] sm1Decrypt(GroupMode mode, int index, byte[] iv, byte[] encodeData) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM1外部密钥加密
     *
     * @param mode 分组模式 ECB/CBC
     * @param key  密钥
     * @param iv   初始向量  CBC模式下需要 ECB模式下传null
     * @param data 待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */

    public byte[] sm1Encrypt(GroupMode mode, byte[] key, byte[] iv, byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM1外部密钥解密
     *
     * @param mode       分组模式 ECB/CBC
     * @param key        密钥
     * @param iv         初始向量  CBC模式下需要 ECB模式下传null
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */

    public byte[] sm1Decrypt(GroupMode mode, byte[] key, byte[] iv, byte[] encodeData) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * 获取SM2签名公钥
     *
     * @param index  索引
     * @param length 密钥长度 256/512
     * @return SM2签名公钥
     * @throws AFCryptoException 获取SM2签名公钥异常
     */

    public SM2PublicKey getSM2SignPublicKey(int index, ModulusLength length) throws AFCryptoException {
        return null;
    }

    /**
     * 获取SM2加密公钥
     *
     * @param index  索引
     * @param length
     * @return SM2加密公钥 默认512位, 如果需要256位, 请调用{@link SM2PublicKey#to256()}
     * @throws AFCryptoException 获取SM2加密公钥异常
     */

    public SM2PublicKey getSM2EncryptPublicKey(int index, ModulusLength length) throws AFCryptoException {
        return null;
    }

    /**
     * 生成SM2密钥对
     *
     * @param length
     * @throws AFCryptoException 生成SM2密钥对异常
     */

    public SM2KeyPair generateSM2KeyPair(ModulusLength length) throws AFCryptoException {
        return null;
    }

    /**
     * SM2内部密钥加密
     *
     * @param length
     * @param index  索引
     * @param data   待加密数据
     * @throws AFCryptoException 加密异常
     */

    public SM2Cipher sm2Encrypt(ModulusLength length, int index, byte[] data) throws AFCryptoException {
        return null;
    }

    /**
     * SM2内部密钥解密
     *
     * @param length
     * @param index      索引
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */

    public byte[] sm2Decrypt(ModulusLength length, int index, SM2Cipher encodeData) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM2外部密钥加密
     *
     * @param length
     * @param key    密钥
     * @param data   待加密数据
     * @return 加密后的数据
     * @throws AFCryptoException 加密异常
     */

    public SM2Cipher sm2Encrypt(ModulusLength length, SM2PublicKey key, byte[] data) throws AFCryptoException {
        return null;
    }

    /**
     * SM2外部密钥解密
     *
     * @param length
     * @param privateKey
     * @param encodeData 待解密数据
     * @return 解密后的数据
     * @throws AFCryptoException 解密异常
     */

    public byte[] sm2Decrypt(ModulusLength length, SM2PrivateKey privateKey, SM2Cipher encodeData) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM2 内部密钥签名
     *
     * @param length
     * @param index  密钥索引
     * @param data   待签名数据
     * @throws AFCryptoException 签名异常
     */

    public SM2Signature sm2Signature(ModulusLength length, int index, byte[] data) throws AFCryptoException {
        return null;
    }

    /**
     * SM2 内部密钥验签
     *
     * @param length
     * @param index     密钥索引
     * @param data      待验签数据
     * @param signature 签名
     * @return 验签结果 true:验签成功 false:验签失败
     * @throws AFCryptoException 验签异常
     */

    public boolean sm2Verify(ModulusLength length, int index, byte[] data, SM2Signature signature) throws AFCryptoException {
        return false;
    }

    /**
     * SM2 外部密钥签名
     *
     * @param length
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return 签名
     * @throws AFCryptoException 签名异常
     */

    public SM2Signature sm2Signature(ModulusLength length, byte[] data, SM2PrivateKey privateKey) throws AFCryptoException {
        return null;
    }

    /**
     * SM2 外部密钥验签
     *
     * @param length
     * @param data      待验签数据
     * @param signature 签名
     * @param publicKey 公钥
     * @return 验签结果 true:验签成功 false:验签失败
     * @throws AFCryptoException 验签异常
     */

    public boolean sm2Verify(ModulusLength length, byte[] data, SM2Signature signature, SM2PublicKey publicKey) throws AFCryptoException {
        return false;
    }


    public byte[] sm3Hash(byte[] data) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * SM3哈希 杂凑算法 <br>
     * 带公钥信息和用户ID
     *
     * @param data      待杂凑数据
     * @param publicKey 公钥 可以传入256/512位公钥 实际计算使用256位公钥
     * @param userID    用户ID
     * @return 杂凑值
     * @throws AFCryptoException 杂凑异常
     */

    public byte[] sm3HashWithPubKey(byte[] data, SM2PublicKey publicKey, byte[] userID) throws AFCryptoException {
        return new byte[0];
    }


    public byte[] SM3HMac(int index, byte[] data) throws AFCryptoException {
        return new byte[0];
    }


    public byte[] SM3HMac(byte[] key, byte[] data) throws AFCryptoException {
        return new byte[0];
    }


    public byte[] sm4Mac(int index, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }


    public byte[] sm4Mac(byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }


    public byte[] sm4Encrypt(GroupMode mode, int index, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }


    public byte[] sm4Decrypt(GroupMode mode, int index, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }


    public byte[] sm4Encrypt(GroupMode mode, byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }


    public byte[] sm4Decrypt(GroupMode mode, byte[] key, byte[] data, byte[] IV) throws AFCryptoException {
        return new byte[0];
    }

    /**
     * <p> 获取RSA签名公钥信息 </p>
     *
     * @param index ：密钥索引
     * @return 返回RSA签名数据结构
     */
    public byte[] getRSASignPublicKey(int index) throws AFCryptoException {
        logger.info("HSM-获取RSA签名公钥信息, index:{}", index);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(ConstantNumber.SGD_RSA_SIGN)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTSIGNPUBLICKEY_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-获取RSA签名公钥信息失败, index:{}, 错误码:{},错误信息:{}", index, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-获取RSA签名公钥信息失败, index:" + index + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p> 获取RSA加密公钥信息 </p>
     *
     * @param index ： 密钥索引
     * @return 返回RSA加密数据结构
     */
    public byte[]  getRSAEncPublicKey(int index) throws AFCryptoException {
        logger.info("HSM-获取RSA加密公钥信息, index:{}", index);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(ConstantNumber.SGD_RSA_ENC)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXPORTENCPUBLICKEY_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-获取RSA加密公钥信息失败, index:{}, 错误码:{},错误信息:{}", index, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-获取RSA加密公钥信息失败, index:" + index + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p> 生成RSA密钥对信息 </p>
     *
     * @param bits : 位长，1024 or 2048
     * @return 返回RSA密钥对数据结构
     */
    public RSAKeyPair generateRSAKeyPair(int bits) throws AFCryptoException {
        logger.info("HSM-生成RSA密钥对信息, bits:{}", bits);
        byte[] param = new BytesBuffer()
                .append(ConstantNumber.SGD_RSA)
                .append(bits)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_GENERATEKEYPAIR_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-生成RSA密钥对信息失败, bits:{}, 错误码:{},错误信息:{}", bits, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-生成RSA密钥对信息失败, bits:" + bits + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        //公钥长度与公钥数据
        int pubKeyLen = BytesOperate.bytes2int(res.getData());
        byte[] pubKeyData = getBytes(res.getData(), 4, pubKeyLen);

        //私钥长度与私钥数据
        int privateKeyLen = BytesOperate.bytes2int(res.getData(), 4 + pubKeyLen);
        byte[] privateKeyData = getBytes(res.getData(), 4 + pubKeyLen + 4, privateKeyLen);

        //解析公钥
        RSAPubKey pubKey = new RSAPubKey();
        pubKey.decode(pubKeyData);

        //解析私钥
        RSAPriKey priKey = new RSAPriKey();
        priKey.decode(privateKeyData);

        return new RSAKeyPair(pubKey, priKey);
    }


    private static byte[] getBytes(byte[] bytesResponse, int offset, int length) {
        return BytesOperate.subBytes(bytesResponse, offset, length);
    }
    /**
     * <p> RSA外部加密运算 </p>
     *
     * @param publicKey ：RSA公钥信息
     * @param data      : 原始数据
     * @return ：返回运算结果
     */

    public byte[] RSAExternalEncode(RSAPubKey publicKey, byte[] data) throws AFCryptoException {
        logger.info("HSM-RSA外部加密运算, publicKey:{}, dataLen:{}", publicKey, data.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(0)
                .append(0)
                .append(publicKey.size())
                .append(publicKey.encode())
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPUBLICKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-RSA外部加密运算失败, dataLen:{}, 错误码:{},错误信息:{}", data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-RSA外部加密运算失败, dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p> RSA外部解密运算 </p>
     *
     * @param prvKey ：RSA私钥信息
     * @param data   : 加密数据
     * @return ：返回运算结果
     */

    public byte[] RSAExternalDecode(RSAPriKey prvKey, byte[] data) throws AFCryptoException {
        logger.info("HSM-RSA外部解密运算, prvKey:{}, dataLen:{}", prvKey, data.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(0)
                .append(0)
                .append(prvKey.size())
                .append(prvKey.encode())
                .append(data.length)
                .append(data)
                .toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPRIVATEKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-RSA外部解密运算失败, dataLen:{}, 错误码:{},错误信息:{}", data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-RSA外部解密运算失败, dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p> RSA外部签名运算 </p>
     *
     * @param prvKey ：RSA私钥信息
     * @param data   : 原始数据
     * @return ：返回运算结果
     */

    public byte[] RSAExternalSign(RSAPriKey prvKey, byte[] data) throws AFCryptoException {
        logger.info("HSM-RSA外部签名运算, prvKey:{}, dataLen:{}", prvKey, data.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(0)
                .append(0)
                .append(prvKey.size())
                .append(prvKey.encode())
                .append(data.length)
                .append(data)
                .toBytes();

        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPRIVATEKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-RSA外部签名运算失败, dataLen:{}, 错误码:{},错误信息:{}", data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-RSA外部签名运算失败, dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p> RSA外部验证签名运算 </p>
     *
     * @param publicKey ：RSA公钥信息
     * @param data      : 签名数据
     * @param rawData   : 原始数据
     * @return ：true: 验证成功，false：验证失败
     */

    public boolean RSAExternalVerify(RSAPubKey publicKey, byte[] data, byte[] rawData) throws AFCryptoException {
        logger.info("HSM-RSA外部验证签名运算, publicKey:{}, dataLen:{}, rawDataLen:{}", publicKey, data.length, rawData.length);
        byte[] param = new BytesBuffer()
                .append(0)
                .append(0)
                .append(0)
                .append(publicKey.size())
                .append(publicKey.encode())
                .append(data.length)
                .append(data)
                .toBytes();

        RequestMessage req = new RequestMessage(CMDCode.CMD_EXTERNALPUBLICKEYOPERATION_RSA, param);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-RSA外部验证签名运算失败, dataLen:{}, rawDataLen:{}, 错误码:{},错误信息:{}", data.length, rawData.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-RSA外部验证签名运算失败, dataLen:" + data.length + ", rawDataLen:" + rawData.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] bytes = res.getDataBuffer().readOneData();
        return Arrays.equals(bytes, rawData);
    }

    /**
     * <p> RSA内部加密运算 </p>
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 原始数据
     * @return ：返回运算结果
     */

    public byte[] RSAInternalEncode(int index, byte[] data) throws AFCryptoException {
        logger.info("HSM-RSA内部加密运算, index:{}, dataLen:{}", index, data.length);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(ConstantNumber.SGD_RSA_ENC)
                .append(0)
                .append(0)
                .append(data.length)
                .append(data)
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_INTERNALPUBLICKEYOPERATION_RSA, param));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-RSA内部加密运算失败, index:{}, dataLen:{}, 错误码:{},错误信息:{}", index, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-RSA内部加密运算失败, index:" + index + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p> RSA内部解密运算 </p>
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 加密数据
     * @return ：返回运算结果
     */

    public byte[] RSAInternalDecode(int index, byte[] data) throws AFCryptoException {
        logger.info("HSM-RSA内部解密运算, index:{}, dataLen:{}", index, data.length);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(ConstantNumber.SGD_RSA_ENC)
                .append(0)
                .append(0)
                .append(data.length)
                .append(data)
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_INTERNALPRIVATEKEYOPERATION_RSA, param));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-RSA内部解密运算失败, index:{}, dataLen:{}, 错误码:{},错误信息:{}", index, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-RSA内部解密运算失败, index:" + index + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();
    }

    /**
     * <p> RSA内部签名运算</p>
     *
     * @param index ：RSA内部密钥索引
     * @param data  : 原始数据
     * @return ：返回运算结果
     */

    public byte[] RSAInternalSign(int index, byte[] data) throws AFCryptoException {
        logger.info("HSM-RSA内部签名运算, index:{}, dataLen:{}", index, data.length);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(ConstantNumber.SGD_RSA_SIGN)
                .append(0)
                .append(0)
                .append(data.length)
                .append(data)
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_INTERNALPRIVATEKEYOPERATION_RSA, param));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-RSA内部签名运算失败, index:{}, dataLen:{}, 错误码:{},错误信息:{}", index, data.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-RSA内部签名运算失败, index:" + index + ", dataLen:" + data.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readOneData();

    }

    /**
     * <p> RSA内部验证签名运算 </p>
     *
     * @param index   ：RSA内部密钥索引
     * @param data    : 签名数据
     * @param rawData : 原始数据
     * @return ：true: 验证成功，false：验证失败
     */

    public boolean RSAInternalVerify(int index, byte[] data, byte[] rawData) throws AFCryptoException {
        logger.info("HSM-RSA内部验证签名运算, index:{}, dataLen:{}, rawDataLen:{}", index, data.length, rawData.length);
        byte[] param = new BytesBuffer()
                .append(index)
                .append(ConstantNumber.SGD_RSA_SIGN)
                .append(0)
                .append(0)
                .append(data.length)
                .append(data)
                .toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_INTERNALPUBLICKEYOPERATION_RSA, param));
        if (res.getHeader().getErrorCode() != 0) {
            logger.error("HSM-RSA内部验证签名运算失败, index:{}, dataLen:{}, rawDataLen:{}, 错误码:{},错误信息:{}", index, data.length, rawData.length, res.getHeader().getErrorCode(), res.getHeader().getErrorInfo());
            throw new AFCryptoException("HSM-RSA内部验证签名运算失败, index:" + index + ", dataLen:" + data.length + ", rawDataLen:" + rawData.length + ", 错误码:" + res.getHeader().getErrorCode() + ",错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] bytes = res.getDataBuffer().readOneData();
        return Arrays.equals(bytes, rawData);
    }


}
