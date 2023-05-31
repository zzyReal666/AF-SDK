package com.af.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 14:41
 */
public enum ConstantNumber {
    ;
    public static final int SGD_TRUE = 0x00000001;
    public static final int SGD_FALSE = 0x00000000;

    public static final int SGD_MODE_MASK = 0x000000FF;
    public static final int SGD_MODE_ECB = 0x00000001;
    public static final int SGD_MODE_CBC = 0x00000002;
    public static final int SGD_MODE_CFB = 0x00000004;
    public static final int SGD_MODE_OFB = 0x00000008;
    public static final int SGD_MODE_MAC = 0x00000010;
    public static final int SGD_MODE_CTR = 0x00000020;

    public static final int SGD_SYMM_MASK = 0x00FFFF00;
    public static final int SGD_SM1 = 0x00000100;
    public static final int SGD_SSF33 = 0x00000200;
    public static final int SGD_SMS4 = 0x00000400;

    public static final int SGD_DES = 0x00001000;
    public static final int SGD_3DES = 0x00002000;
    public static final int SGD_AES = 0x00004000;

    /**
     * 算法标识 0006 标准
     */
    public static final int SGD_SM1_ECB = 0x00000101;
    public static final int SGD_SM1_CBC = 0x00000102;
    public static final int SGD_SM1_CFB = 0x00000104;
    public static final int SGD_SM1_OFB = 0x00000108;
    public static final int SGD_SM1_MAC = 0x00000110;
    public static final int SGD_SM1_CTR = 0x00000120; //user-defined

    public static final int SGD_SSF33_ECB = 0x00000201;
    public static final int SGD_SSF33_CBC = 0x00000202;
    public static final int SGD_SSF33_CFB = 0x00000204;
    public static final int SGD_SSF33_OFB = 0x00000208;
    public static final int SGD_SSF33_MAC = 0x00000210;
    public static final int SGD_SSF33_CTR = 0x00000220;//user-defined

    public static final int SGD_SMS4_ECB = 0x00000401;
    public static final int SGD_SMS4_CBC = 0x00000402;
    public static final int SGD_SMS4_CFB = 0x00000404;
    public static final int SGD_SMS4_OFB = 0x00000408;
    public static final int SGD_SMS4_MAC = 0x00000410;
    public static final int SGD_SMS4_CTR = 0x00000420; //user-defined

    public static final int SGD_ZUC_EEA3 = 0x00000801;
    public static final int SGD_ZUC_EIA3 = 0x00000802;

    public static final int SGD_RSA = 0x00010000;
    public static final int SGD_RSA_SIGN = 0x00010010; //user-defined
    public static final int SGD_RSA_ENC = 0x00010020;//user-defined

    public static final int SGD_SM2 = 0x00020100;     //生成sm2密钥对
    public static final int SGD_SM2_1 = 0x00020200;  //获取sm2签名公钥    //SM2外部密钥签名
    public static final int SGD_SM2_2 = 0x00020400;  //获取sm2加密公钥
    public static final int SGD_SM2_3 = 0x00020800;  //SM2 内部加密/解密

    public static final int SGD_SM3 = 0x00000001;
    public static final int SGD_SM3_MAC = 0x00010001;
    public static final int SGD_SHA1 = 0x00000002;
    public static final int SGD_SHA256 = 0x00000004;
    public static final int SGD_SHA384 = 0x00000008;
    public static final int SGD_SHA512 = 0x00000010;
    public static final int SGD_SHA224 = 0x00000020;
    public static final int SGD_MD5 = 0x00000040;

    public static final int SGD_DES_ECB = 0x00001001; //user-defined
    public static final int SGD_DES_CBC = 0x00001002; //user-defined
    public static final int SGD_DES_CFB = 0x00001004; //user-defined
    public static final int SGD_DES_OFB = 0x00001008; //user-defined
    public static final int SGD_DES_MAC = 0x00001010; //user-defined
    public static final int SGD_DES_CTR = 0x00001020; //user-defined

    public static final int SGD_3DES_ECB = 0x00002001; //user-defined
    public static final int SGD_3DES_CBC = 0x00002002; //user-defined
    public static final int SGD_3DES_CFB = 0x00002004; //user-defined
    public static final int SGD_3DES_OFB = 0x00002008; //user-defined
    public static final int SGD_3DES_MAC = 0x00002010; //user-defined
    public static final int SGD_3DES_CTR = 0x00002020; //user-defined

    public static final int SGD_AES_ECB = 0x00004001; //user-defined
    public static final int SGD_AES_CBC = 0x00004002; //user-defined
    public static final int SGD_AES_CFB = 0x00004004; //user-defined
    public static final int SGD_AES_OFB = 0x00004008; //user-defined
    public static final int SGD_AES_MAC = 0x00004010; //user-defined
    public static final int SGD_AES_CTR = 0x00004020; //user-defined

    public static final int MAX_KEY_LENGTH = 32;
    public static final int MAX_RSA_KEY_PAIR_COUNT = 63;
    // public static final int  MAX_RSA_KEY_PAIR_COUNT_09 = 80;
    // public static final int  MAX_RSA_KEY_PAIR_COUNT_12 = 50;
    // public static final int  MAX_RSA_KEY_PAIR_COUNT_16 = 60;
    public static final int MAX_ECC_KEY_PAIR_COUNT = 1023;  //最大密钥对数
    public static final int MAX_KEK_COUNT = 2047;
    public static final int MAX_SESSION_KEY_COUNT = 1024;

    public static final int KEY_TYPE_ECDSA = 7;
    public static final int KEY_TYPE_DSA = 6;
    public static final int KEY_TYPE_RSA_EX = 5;
    public static final int KEY_TYPE_RSA = 4;    //获取密钥状态时对应RSA非对称密钥类型
    public static final int KEY_TYPE_RSA_DER = 0x14;   //DER格式密钥
    public static final int KEY_TYPE_ECC = 3;    //获取密钥状态时对应ECC非对称密钥类型
    public static final int KEY_TYPE_SESSION_KEY = 2;     //获取密钥状态时对应易失性对称密钥类型
    public static final int KEY_TYPE_KEK = 1;     //获取密钥状态时对应非易失性对称密钥类型
    public static final int KEY_TYPE_EXTERNAL_KEY = 0;

    public static final int BLX_KEYTPYE_DEC = 0;
    public static final int BLX_KEYTPYE_ENC = 2;


    public static final int AF_LEN_1024 = 1024;
    public static final int AF_LEN_2048 = 2048;
    public static final int AF_LEN_4096 = 1024 * 512;
    public static final int AF_LEN_MAX = 4096 + 4096;

    public static final int LiteRSARef_MAX_BITS = 2048;
    public static final int LiteRSARef_MAX_LEN = ((LiteRSARef_MAX_BITS + 7) / 8);
    public static final int LiteRSARef_MAX_PBITS = ((LiteRSARef_MAX_BITS + 1) / 2);
    public static final int LiteRSARef_MAX_PLEN = ((LiteRSARef_MAX_PBITS + 7) / 8);


    //签名验签服务器
    public static final int SIGN_PUBLIC_KEY = 0;   //签名公钥
    public static final int ENC_PUBLIC_KEY = 1;   //加密公钥
    public static final String DEFAULT_USER_ID = "1234567812345678";
    public static final int SGD_SERVER_CERT_SIGN = 2;           ///< 服务器签名证书
    public static final int SGD_SERVER_CERT_ENC = 1;          ///< 服务器加密证书

    public static final int SGD_CERT_SIGN = 2;           ///< 签名证书
    public static final int SGD_CERT_ENC = 1;

}
