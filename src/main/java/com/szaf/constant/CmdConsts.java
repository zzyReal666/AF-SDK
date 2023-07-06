package com.szaf.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 17:53
 */
public enum CmdConsts {
    ;
    public static final int CMD_LOGIN = 0x00000000; // 登录
    public static final int CMD_ENCRYPT = 0x00100001;
    public static final int CMD_DECRYPT = 0x00100002;

    public static final int CMD_DEVICEINFO = 0x00020001;
    public static final int CMD_GENERATERANDOM = 0x00020002;

    public static final int CMD_EXPORTSIGNPUBLICKEY_RSA = 0x00040001;
    public static final int CMD_EXPORTENCPUBLICKEY_RSA = 0x00040001;
    public static final int CMD_GENERATEKEYPAIR_RSA = 0x00040002;

    public static final int CMD_EXCHANGEDIGITENVELOPEBASEONRSA = 0x00040005;

    public static final int CMD_EXPORTSIGNPUBLICKEY_ECC = 0x00040001;
    public static final int CMD_EXPORTENCPUBLICKEY_ECC = 0x00040001;
    public static final int CMD_GENERATEKEYPAIR_ECC = 0x00040002;


    public static final int CMD_GETPRIVATEKEYACCESSRIGHT = 0x00040007;

    public static final int CMD_EXTERNALPUBLICKEYOPERATION_RSA = 0x00080001;
    public static final int CMD_EXTERNALPRIVATEKEYOPERATION_RSA = 0x00080002;

    public static final int CMD_INTERNALPUBLICKEYOPERATION_RSA = 0x00080001;
    public static final int CMD_INTERNALPRIVATEKEYOPERATION_RSA = 0x00080002;

    public static final int CMD_EXTERNALSIGN_ECC = 0x00080003;
    public static final int CMD_EXTERNALVERIFY_ECC = 0x00080004;

    public static final int CMD_INTERNALSIGN_ECC = 0x00080003;
    public static final int CMD_INTERNALVERIFY_ECC = 0x00080004;

    public static final int CMD_EXTERNALENCRYPT_ECC = 0x00080005;
    public static final int CMD_EXTERNALDECRYPT_ECC = 0x00080006;

    public static final int CMD_CALCULATEMAC = 0x00100003;


    public static final int CMD_EXPORT_KEY = 0x00400005;
    public static final int CMD_INPUT_KEK = 0x01020019;
    public static final int CMD_DELETE_KEK = 0x0102001a;
    public static final int CMD_SEND_LOCAL_KEY_AGREEMENT_PUBLIC_KEY_CIPHER_TEXT = 0x0102002b; // 交换公钥
    public static final int CMD_GENERATE_NEGOTIATION_KEY = 0x0102002c; // 交换随机数
    public static final int CMD_GET_KEY_STATUS = 0x01020008;


    public static final int CMD_GENERATE_RANDOM = 0x00020002;
    public static final int CMD_GENERATE_KEY_PAIR_RSA = 0x00040002;
    public static final int CMD_GENERATE_KEY_PAIR_SM2 = 0x00040002;
    public static final int CMD_GET_PRIVATE_KEY_ACCESS_RIGHT = 0x00040007;

}
