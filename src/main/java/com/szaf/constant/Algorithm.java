package com.szaf.constant;

import lombok.Getter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 算法标识定义 根据协议2.0
 * @since 2023/5/31 15:38
 */
@Getter
public enum Algorithm {


    //1 SGD_SM1_ECB 0x00000101 SM1 算法 ECB 加密模式
    //2 SGD_SM1_CBC 0x00000102 SM1 算法 CBC 加密模式
    //3 SGD_SM2 0x00020100 SM2 椭圆曲线算法
    //4 SGD_SM2_1 0x00020200 SM2 椭圆曲线签名算法
    //5 SGD_SM2_2 0x00020400 SM2 椭圆曲线密钥交换协议
    //6 SGD_SM2_3 0x00020800 SM2 椭圆曲线加密算法
    //7 SGD_SM3 0x00000001 SM3 杂凑算法
    //8 SGD_SMS4_ECB 0x00000401 SM4 算法 ECB 加密模式
    //9 SGD_SMS4_CBC 0x00000402 SM4 算法 CBC 加密模式
    //10 SGD_RSA 0x00010000 RSA 非对称算法
    //11 SGD_RSA_SIGN 0x00010010 RSA 非对称签名算法
    //12 SGD_RSA_ENC 0x00010020 RSA 非对称加密算法

    SGD_SM1_ECB("SM1 ECB", 0x00000101),
    SGD_SM1_CBC("SM1 CBC", 0x00000102),

    SGD_SM2("SM2", 0x00020100),       //椭圆曲线算法
    SGD_SM2_1("SM2_1", 0x00020200),   //SM2签名
    SGD_SM2_2("SM2_2", 0x00020400),   //SM2密钥交换
    SGD_SM2_3("SM2_3", 0x00020800),   //SM2加密

    SGD_SM3("SM3", 0x00000001),

    SGD_SMS4_ECB("SM4 ECB", 0x00000401),
    SGD_SMS4_CBC("SM4 CBC", 0x00000402),

    SGD_RSA("RSA", 0x00010000),
    SGD_RSA_SIGN("RSA SIGN", 0x00010010),  //RSA签名
    SGD_RSA_ENC("RSA ENC", 0x00010020);    //RSA加密

    private final String name;
    private final int value;

    Algorithm(String name, int value) {
        this.name = name;
        this.value = value;
    }

}
