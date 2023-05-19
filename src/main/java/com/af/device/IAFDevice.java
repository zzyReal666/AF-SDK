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
import com.af.utils.Sm2Utils;

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


    default byte[] keyAgreement(AFNettyClient client) throws AFCryptoException {
        /*
         * 1、生成公私钥对
         */
        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        SM2 sm2 = SmUtil.sm2(pair.getPrivate(), pair.getPublic());
        byte[] pubKey = Sm2Utils.changePublicKeyQTo512(sm2.getQ(false));
        byte[] priKey = sm2.getD();
        priKey = priKey.length == 32 ? priKey : ArrayUtil.sub(priKey, priKey.length - 32, priKey.length);

        /*
         * 2、交换公钥
         */
        SM4 sm4Padding = new SM4(Mode.ECB, Padding.PKCS5Padding, ROOT_KEY);
        byte[] cPubKey = sm4Padding.encrypt(pubKey);
        byte[] data = new BytesBuffer().append(cPubKey.length).append(cPubKey).toBytes();
        RequestMessage requestMessage = new RequestMessage(CMDCode.CMD_EXCHANGE_PUBLIC_KEY, data);
        ResponseMessage res = client.send(requestMessage);
        if (res.getHeader().getErrorCode() != 0) {
            throw new DeviceException("密钥协商失败，错误码:" + res.getHeader().getErrorCode() + "，错误信息:" + res.getHeader().getErrorInfo());
        }
        byte[] cServerPubKey = res.getDataBuffer().readOneData();
        SM4 sm4NoPadding = new SM4(Mode.ECB, Padding.NoPadding, ROOT_KEY);
        byte[] serverPubKey = sm4NoPadding.decrypt(cServerPubKey); // 服务器公钥

        /*
         * 3、产生随机数ra，私钥签名，公钥加密
         */
        byte[] ra = RandomUtil.getSecureRandom().generateSeed(16);
        byte[] raSign = Sm2Utils.sign(priKey, ra); // 使用私钥对ra签名
        byte[] raCipher = Sm2Utils.encrypt(serverPubKey, ra); // 使用服务器公钥对ra加密

        /*
         * 4、交换随机数，得到rab，私钥解密，公钥验签
         */
        data = new BytesBuffer().append(raCipher.length).append(raCipher).append(raSign.length).append(raSign).toBytes();
        res = client.send(new RequestMessage(CMDCode.CMD_EXCHANGE_RANDOM, data));


        byte[] rabCipher = res.getDataBuffer().readOneData();
        byte[] rbSign = res.getDataBuffer().readOneData();
        byte[] rab = Sm2Utils.decrypt(priKey, rabCipher); // 使用私钥解密rab
        if (!ArrayUtil.equals(ra, ArrayUtil.sub(rab, 0, 16))) { // 对比ra
            throw new DeviceException("密钥协商失败，对比客户端随机数不一致");
        }
        byte[] rb = ArrayUtil.sub(rab, 16, 32);
        if (!Sm2Utils.verify(serverPubKey, rb, rbSign)) { // 验证rb签名
            throw new DeviceException("密钥协商失败，验证服务端随机数不通过");
        }

        /*
         * 5、计算协商密钥
         */
        byte[] agreementKey = new byte[16];
        for (int i = 0; i < 16; i++) {
            agreementKey[i] = (byte) (ra[i] ^ rb[i]);
        }
        return agreementKey;
    }


}
