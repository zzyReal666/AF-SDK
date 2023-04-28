package com.af.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 密钥模长 256/512
 * @since 2023/4/28 16:23
 */
public enum ModulusLength {

    LENGTH_256(256),
    LENGTH_512(512);

    private final int length;

    ModulusLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }

}
