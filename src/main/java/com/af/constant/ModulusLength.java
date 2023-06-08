package com.af.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/28 16:23
 */
public enum ModulusLength {

    LENGTH_256(256),
    LENGTH_512(512),
    LENGTH_1024(1024),
    LENGTH_2048(2048);


    private final int length;

    ModulusLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }

}
