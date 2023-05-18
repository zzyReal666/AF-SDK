package com.af.device.impl;

import com.af.exception.AFCryptoException;
import com.af.netty.AFNettyClient;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/6 11:19
 */
public class AFCryptoDevice extends AFHsmDevice {

    private static AFNettyClient client = null;

    //私有化构造方法
    private AFCryptoDevice(AFNettyClient client) {
        super();
    }
    //静态内部类单例
    private static class SingletonHolder {
        private static final AFCryptoDevice INSTANCE = new AFCryptoDevice(client);
    }
    //获取单例
    public static AFCryptoDevice getInstance(String host, int port, String passwd) {
        client = AFNettyClient.getInstance(host, port, passwd);
        return SingletonHolder.INSTANCE;
    }



    /**
     * 获取随机数
     *
     * @param length 随机数长度
     * @return 随机数
     * @throws AFCryptoException 获取随机数异常
     */
    public byte[] getRandom(int length) throws AFCryptoException {
        //TODO: 2023/5/6 11:19 获取随机数增强
        return super.getRandom(length);
    }


}
