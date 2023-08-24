package com.af.constant;

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
    //8 SGD_SM4_ECB 0x00000401 SM4 算法 ECB 加密模式
    //9 SGD_SM4_CBC 0x00000402 SM4 算法 CBC 加密模式
    //10 SGD_RSA 0x00010000 RSA 非对称算法
    //11 SGD_RSA_SIGN 0x00010010 RSA 非对称签名算法
    //12 SGD_RSA_ENC 0x00010020 RSA 非对称加密算法

    SGD_SM1_ECB("SM1 ECB", 0x00000101),
    SGD_SM1_CBC("SM1 CBC", 0x00000102),
    SGD_SM1_CFB("SM1 CFB", 0x00000104),
    SGD_SM1_OFB("SM1 OFB", 0x00000108),
    SGD_SM1_MAC("SM1 MAC", 0x00000110),
    SGD_SM1_CTR("SM1 CTR", 0x00000120),


    SGD_SM2("SM2", 0x00020100),       //椭圆曲线算法
    SGD_SM2_1("SM2_1", 0x00020200),   //SM2签名
    SGD_SM2_2("SM2_2", 0x00020400),   //SM2密钥交换
    SGD_SM2_3("SM2_3", 0x00020800),   //SM2加密

    SGD_SM3("SM3", 0x00000001),

    SGD_SM4_ECB("SM4 ECB", 0x00000401),
    SGD_SM4_CBC("SM4 CBC", 0x00000402),
    SGD_SM4_CFB("SM4 CFB", 0x00000404),
    SGD_SM4_OFB("SM4 OFB", 0x00000408),
    SGD_SM4_MAC("SM4 MAC", 0x00000410),
    SGD_SM4_CTR("SM4 CTR", 0x00000420),


    SGD_RSA("RSA", 0x00010000),
    SGD_RSA_SIGN("RSA SIGN", 0x00010010),  //RSA签名
    SGD_RSA_ENC("RSA ENC", 0x00010020),    //RSA加密


    SGD_DES_ECB("DES ECB", 0x00001001),
    SGD_DES_CBC("DES CBC", 0x00001002),
    SGD_DES_CFB("DES CFB", 0x00001004),
    SGD_DES_OFB("DES OFB", 0x00001008),
    SGD_DES_MAC("DES MAC", 0x00001010),
    SGD_DES_CTR("DES CTR", 0x00001020),

    //3DES-2KEY
    SGD_2DES_ECB("3DES-2KEY ECB", 0x01000001),
    SGD_2DES_CBC("3DES-2KEY CBC", 0x01000002),
    SGD_2DES_CFB("3DES-2KEY CFB", 0x01000004),
    SGD_2DES_OFB("3DES-2KEY OFB", 0x01000008),
    SGD_2DES_MAC("3DES-2KEY MAC", 0x01000010),
    SGD_2DES_CTR("3DES-2KEY CTR", 0x01000020),

    //3DES-3KEY
    SGD_3DES_ECB("3DES-3KEY ECB", 0x00002001),
    SGD_3DES_CBC("3DES-3KEY CBC", 0x00002002),
    SGD_3DES_CFB("3DES-3KEY CFB", 0x00002004),
    SGD_3DES_OFB("3DES-3KEY OFB", 0x00002008),
    SGD_3DES_MAC("3DES-3KEY MAC", 0x00002010),
    SGD_3DES_CTR("3DES-3KEY CTR", 0x00002020),

    SGD_AES_ECB("AES-128 ECB", 0x00004001),
    SGD_AES_CBC("AES-128 CBC", 0x00004002),
    SGD_AES_CFB("AES-128 CFB", 0x00004004),
    SGD_AES_OFB("AES-128 OFB", 0x00004008),
    SGD_AES_MAC("AES-128 MAC", 0x00004010),
    SGD_AES_CTR("AES-128 CTR", 0x00004020),

    SGD_AES192_ECB("AES-192 ECB", 0x02000001),
    SGD_AES192_CBC("AES-192 CBC", 0x02000002),
    SGD_AES192_CFB("AES-192 CFB", 0x02000004),
    SGD_AES192_OFB("AES-192 OFB", 0x02000008),
    SGD_AES192_MAC("AES-192 MAC", 0x02000010),
    SGD_AES192_CTR("AES-192 CTR", 0x02000020);


    private final String name;
    private final int value;

    Algorithm(String name, int value) {
        this.name = name;
        this.value = value;
    }

    //根据name 获取
    public static Algorithm getAlgorithmByName(String name) {
        for (Algorithm algorithm : Algorithm.values()) {
            if (algorithm.getName().equals(name)) {
                return algorithm;
            }
        }
        return null;
    }

    //根据value 获取
    public static Algorithm getAlgorithmByValue(int value) {
        for (Algorithm algorithm : Algorithm.values()) {
            if (algorithm.getValue() == value) {
                return algorithm;
            }
        }
        return null;
    }


}
