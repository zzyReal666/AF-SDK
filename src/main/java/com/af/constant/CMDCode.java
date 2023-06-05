package com.af.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/6 10:28
 */
public enum CMDCode {
    ;
    public static final int CMD_ENCRYPT = 0x00100001;  //对称加密
    public static final int CMD_DECRYPT = 0x00100002;  //对称解密
    public static final int CMD_ENCRYPT_BATCH = 0x00100004;
    public static final int CMD_DECRYPT_BATCH = 0x00100005;

    public static final int CMD_DEVICEINFO = 0x00020001;
    public static final int CMD_GENERATERANDOM = 0x00020002;   //生成随机数

    public static final int CMD_EXPORTSIGNPUBLICKEY_RSA = 0x00040001;
    public static final int CMD_EXPORTENCPUBLICKEY_RSA = 0x00040001;
    public static final int CMD_GENERATEKEYPAIR_RSA = 0x00040002;


    public static final int CMD_EXPORTSIGNPUBLICKEY_ECC = 0x00040001;  //导出签名公钥
    public static final int CMD_EXPORTENCPUBLICKEY_ECC = 0x00040001;   //导出加密公钥


    public static final int CMD_GENERATEKEYPAIR_ECC = 0x00040002;


    public static final int CMD_GETPRIVATEKEYACCESSRIGHT = 0x00040007;

    public static final int CMD_EXTERNALPUBLICKEYOPERATION_RSA = 0x00080001; //RSA公钥运算
    public static final int CMD_EXTERNALPRIVATEKEYOPERATION_RSA = 0x00080002; //RSA私钥运算

    public static final int CMD_INTERNALPUBLICKEYOPERATION_RSA = 0x00080001;  //RSA公钥运算
    public static final int CMD_INTERNALPRIVATEKEYOPERATION_RSA = 0x00080002; //RSA私钥运算

    public static final int CMD_EXTERNALSIGN_ECC = 0x00080003;
    public static final int CMD_EXTERNALVERIFY_ECC = 0x00080004;

    public static final int CMD_INTERNALSIGN_ECC = 0x00080003;
    public static final int CMD_INTERNALVERIFY_ECC = 0x00080004;

    public static final int CMD_EXTERNALENCRYPT_ECC = 0x00080005;   //SM2内部加密
    public static final int CMD_EXTERNALDECRYPT_ECC = 0x00080006;

    public static final int CMD_CALCULATEMAC = 0x00100003;  //计算MAC SM1 SM4
    public static final int CMD_CALCULATEHASH = 0x00500010;  //计算 SM3 HASH
    public static final int CMD_HASHINIT = 0x00500011;  //HASH init
    public static final int CMD_HASHUPDATE = 0x00500012; //HASH update
    public static final int CMD_HASHFINAL = 0x00500013;  //HASH final


    public static final int CMD_EXPORT_KEY = 0x00400005;
    public static final int CMD_INPUT_KEK = 0x01020019;
    public static final int CMD_DELETE_KEK = 0x0102001a;
    public static final int CMD_SEND_LOCAL_KEY_AGREEMENT_PUBLIC_KEY_CIPHER_TEXT = 0x0102002b;
    public static final int CMD_GENERATE_NEGOTIATION_KEY = 0x0102002c;
    public static final int CMD_GET_KEY_STATUS = 0x01020008;


    public static final int CMD_GENERATE_RANDOM = 0x00020002;
    public static final int CMD_GENERATE_KEY_PAIR_RSA = 0x00040002;
    public static final int CMD_GENERATE_KEY_PAIR_SM2 = 0x00040002;
    public static final int CMD_GET_PRIVATE_KEY_ACCESS_RIGHT = 0x00040007;


    // -------------------公用----------------------

    public static final int CMD_LOGIN = 0x00000000;  //登录
    public static final int CMD_EXCHANGE_PUBLIC_KEY = 0x0102002b;  //交换公钥
    public static final int CMD_EXCHANGE_RANDOM = 0x0102002c;  //交换随机数

    // -------------------时间戳服务器----------------------

    public static final int CMD_CREATE_TS_REQUEST = 0x04000001; //创建时间戳请求
    public static final int CMD_TS_RESPONSE = 0x04000002; //时间戳回复
    public static final int CMD_TS_VERIFY = 0x04000003;   //验证时间戳
    public static final int CMD_GET_TS_INFO = 0x04000004;         //获取时间戳主要信息
    public static final int CMD_GET_TS_DETAIL = 0x04000005;      //获取时间戳详细信息

    // -------------------签名验签服务器----------------------


    public static final int CMD_GENERATEKEYWITHIPK_RSA = 0x00040003;  //生成 会话密钥
    public static final int CMD_GENERATEKEYWITHEPK_RSA = 0x00040003;
    public static final int CMD_IMPORTKEYWITHISK_RSA = 0x00040004;  //导入会话密钥


    public static final int CMD_GENERATEKEYWITHIPK_ECC = 0x00040003;
    public static final int CMD_GENERATEKEYWITHEPK_ECC = 0x00040003;
    public static final int CMD_IMPORTKEYWITHISK_ECC = 0x00040004;
    public static final int CMD_EXCHANGEDIGITENVELOPEBASEONECC = 0x00040005;
    public static final int CMD_GENERATEAGREEMENTDATAWITHECC = 0x00040006;
    public static final int CMD_GENERATEAGREEMENTDATAANDKEYWITHECC = 0x00040006;
    public static final int CMD_GENERATEKEYWITHECC = 0x00040006;


    public static final int CMD_DESTROYKEY = 0x0004000a;
    public static final int CMD_GENERATEKEYWITHKEK = 0x0004000b;  //生成会话密钥
    public static final int CMD_IMPORTKEYWITHKEK = 0x0004000c;


    public static final int CMD_CREATEFILE = 0x00400001;
    public static final int CMD_READFILE = 0x00400002;
    public static final int CMD_WRITEFILE = 0x00400003;
    public static final int CMD_DELETEFILE = 0x00400004;


    public static final int CMD_USER_LOGIN = 0x00010001;
    public static final int CMD_ADD_CA_CERT = 0x00010002;
    public static final int CMD_GET_CERT_COUNT = 0x00010003;
    public static final int CMD_GET_ALL_ALT_NAME = 0x00010004;  //获取所有可用的证书别名
    public static final int CMD_GET_CERT = 0x00010005;
    public static final int CMD_DELETE_CERT = 0x00010006;
    public static final int CMD_VERIFY_CERT_BY_CRL = 0x00010008;
    public static final int CMD_GET_CERT_INFO = 0x00010009;    //获取证书信息
    public static final int CMD_GET_CERT_EXT_TYPE_INFO = 0x0001000A;
    public static final int CMD_GET_SERVER_CERT_INFO = 0x0001000B;
    public static final int CMD_GET_INSTANCE = 0x0001000C;
    public static final int CMD_GET_CA_CERT_ALTNAME = 0x0001000D;
    public static final int CMD_GET_CERT_BY_POLICY_NAME = 0x0001000F;
    public static final int CMD_SM2_SIGNDATA_ENCODE = 0x00010821;
    public static final int CMD_SM2_SIGNDATA_DECODE = 0x00010822;
    public static final int CMD_SM2_SIGNDATA_VERIFY = 0x00010823;
    public static final int CMD_CLOSE = 0x0002000B;


    //2023 05 31 根据协议新增

    public static final int EXPORT_PUBLIC_KEY = 0x00040001;     //导出公钥

    public static final int RSA_PUBLIC_KEY_OPERATE = 0x00080001;  //RSA公钥运算

    public static final int RSA_PRIVATE_KEY_OPERATE = 0x00080002;  //RSA私钥运算

    public static final int CMD_VERIFY_CERT = 0x00010007;   //验证证书

    public static final int PKCS7_ENCODE_WITH_SIGN = 0x00010824; //PKCS7 带签名信息的数字信封编码

    public static final int PKCS7_DECODE_WITH_SIGN = 0x00010825;

    public static final int CMD_GETSYMKEYHANDLE = 0x00020005;  //获取对称密钥句柄

    public static final int CMD_GENERATEKEY_ECC = 0x00040003; //生成会话密钥

    public static final int CMD_IMPORTKEY_ECC = 0x00040004;  //导入会话密钥

    public static final int CMD_CONVERTKEY_ECC = 0x00040005; //数字信封转换
}

