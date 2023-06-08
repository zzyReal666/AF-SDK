package com.af.device;


import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.SM4;
import com.af.bean.RequestMessage;
import com.af.bean.ResponseMessage;
import com.af.constant.CMDCode;
import com.af.exception.AFCryptoException;
import com.af.exception.DeviceException;
import com.af.netty.AFNettyClient;
import com.af.utils.BytesBuffer;
import com.af.utils.Sm2Util;

import java.security.KeyPair;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 设备接口 用于获取密码机的设备信息、随机数、密钥信息等
 * @since 2023/4/18 10:57
 */

public interface IAFDevice {


    byte[] ROOT_KEY = {(byte) 0x46, (byte) 0xd3, (byte) 0xf4, (byte) 0x6d, (byte) 0x2e, (byte) 0xc2, (byte) 0x4a, (byte) 0xae, (byte) 0xb1, (byte) 0x84, (byte) 0x62,
            (byte) 0xdd, (byte) 0x86, (byte) 0x23, (byte) 0x71, (byte) 0xed};

    //=======================================================设备信息=======================================================

    /**
     * 获取设备信息
     *
     * @return 设备信息
     * @throws AFCryptoException 获取设备信息异常
     */
    DeviceInfo getDeviceInfo() throws AFCryptoException;


    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * @throws AFCryptoException 获取随机数异常
     */
    byte[] getRandom(int length) throws AFCryptoException;


    default byte[] keyAgreement(AFNettyClient client) {
        /*
         * 1、生成公私钥对
         */
        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        SM2 sm2 = SmUtil.sm2(pair.getPrivate(), pair.getPublic());
        byte[] pubKey = Sm2Util.changePublicKeyQTo512(sm2.getQ(false));
        byte[] priKey = sm2.getD();
        priKey = priKey.length == 32 ? priKey : ArrayUtil.sub(priKey, priKey.length - 32, priKey.length);

        /*
         * 2、交换公钥
         */
        SM4 sm4Padding = new SM4(Mode.ECB, Padding.PKCS5Padding, ROOT_KEY);
        byte[] cPubKey = sm4Padding.encrypt(pubKey);  //只对公钥加密 长度不加密
        byte[] data = new BytesBuffer().append(cPubKey.length).append(cPubKey).toBytes();
        ResponseMessage res = client.send(new RequestMessage(CMDCode.CMD_EXCHANGE_PUBLIC_KEY, data,null));
        if (res.getHeader().getErrorCode() != 0) {
            throw new DeviceException("密钥协商失败，交换公钥服错误,错误码：" + res.getHeader().getErrorCode() + ",错误信息：" + res.getHeader().getErrorInfo());
        }
        byte[] cServerPubKey = res.getDataBuffer().readOneData();
        SM4 sm4NoPadding = new SM4(Mode.ECB, Padding.NoPadding, ROOT_KEY);
        byte[] serverPubKey = sm4NoPadding.decrypt(cServerPubKey); // 服务器公钥

        /*
         * 3、产生随机数ra，私钥签名，公钥加密
         */
        byte[] ra = RandomUtil.getSecureRandom().generateSeed(16);
        byte[] raSign = Sm2Util.sign(priKey, ra); // 使用私钥对ra签名
        byte[] raCipher = Sm2Util.encrypt(serverPubKey, ra); // 使用服务器公钥对ra加密

        /*
         * 4、交换随机数，得到rab，私钥解密，公钥验签
         */
        data = new BytesBuffer().append(raCipher.length).append(raCipher).append(raSign.length).append(raSign).toBytes();
        res = client.send(new RequestMessage(CMDCode.CMD_EXCHANGE_RANDOM, data,null));
        if (res.getHeader().getErrorCode() != 0) {
            throw new DeviceException("密钥协商失败，交换随机数错误,错误码：" + res.getHeader().getErrorCode() + ",错误信息：" + res.getHeader().getErrorInfo());
        }

        BytesBuffer dataBuffer = res.getDataBuffer();
        byte[] rabCipher = dataBuffer.readOneData();
        byte[] rbSign = dataBuffer.readOneData();
        byte[] rab = Sm2Util.decrypt(priKey, rabCipher); // 使用私钥解密rab
        if (!ArrayUtil.equals(ra, ArrayUtil.sub(rab, 0, 16))) { // 对比ra
            throw new DeviceException("密钥协商失败，对比客户端随机数不一致");
        }
        byte[] rb = ArrayUtil.sub(rab, 16, 32);
        if (!Sm2Util.verify(serverPubKey, rb, rbSign)) { // 验证rb签名
            throw new DeviceException("密钥协商失败，验证服务端随机数不通过");
        }

        /*
         * 5、计算协商密钥
         */
        byte[] agreementKey = new byte[16];
        for (int i = 0; i < 16; i++) {
            agreementKey[i] = (byte) (ra[i] ^ rb[i]);
        }
//        return agreementKey;
        return ROOT_KEY;
    }


    /**
     * 关闭连接
     */
    default void close(AFNettyClient client) {
        RequestMessage req = new RequestMessage(CMDCode.CMD_CLOSE).setIsEncrypt(false);
        ResponseMessage send = client.send(req);
        if (send.getHeader().getErrorCode() != 0) {
            throw new DeviceException("关闭连接失败，错误码：" + send.getHeader().getErrorCode() + ",错误信息：" + send.getHeader().getErrorInfo());
        }
    }

    //心跳
    default int heartBeat(AFNettyClient client,int id) {
        byte[] param = new BytesBuffer().append(id).toBytes();
        RequestMessage req = new RequestMessage(CMDCode.CMD_HEART_BEAT,param,null).setIsEncrypt(false);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            throw new DeviceException("心跳失败，错误码：" + res.getHeader().getErrorCode() + ",错误信息：" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readInt();
    }

    //获取连接个数
    default int getConnectCount(AFNettyClient client) {
        RequestMessage req = new RequestMessage(CMDCode.CMD_GET_CONNECT_COUNT).setIsEncrypt(false);
        ResponseMessage res = client.send(req);
        if (res.getHeader().getErrorCode() != 0) {
            throw new DeviceException("获取连接个数失败，错误码：" + res.getHeader().getErrorCode() + ",错误信息：" + res.getHeader().getErrorInfo());
        }
        return res.getDataBuffer().readInt();
    }


}
