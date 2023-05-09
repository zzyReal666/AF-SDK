package com.af.device.impl;

import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/6 11:19
 */
public class AFCryptoDevice extends AFHsmDevice {

    private static volatile AFCryptoDevice instance;

    private AFCryptoDevice(String host, int port, String passwd) {
        super(host, port, passwd);
    }

    public static AFCryptoDevice getInstance(String host, int port, String passwd) {
        if (instance == null) {
            synchronized (AFCryptoDevice.class) {
                if (instance == null) {
                    instance = new AFCryptoDevice(host, port, passwd);
                }
            }
        }
        return instance;
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
