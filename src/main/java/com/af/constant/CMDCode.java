package com.af.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/6 10:28
 */
public enum CMDCode {
    ;
    public static final int CMD_ENCRYPT = 0x00100001;
    public static final int CMD_DECRYPT = 0x00100002;

    public static final int CMD_DEVICEINFO = 0x00020001;
    public static final int CMD_GENERATERANDOM = 0x00020002;   //生成随机数

    public static final int CMD_EXPORTSIGNPUBLICKEY_RSA = 0x00040001;
    public static final int CMD_EXPORTENCPUBLICKEY_RSA = 0x00040001;
    public static final int CMD_GENERATEKEYPAIR_RSA = 0x00040002;

    public static final int CMD_EXCHANGEDIGITENVELOPEBASEONRSA = 0x00040005;

    public static final int CMD_EXPORTSIGNPUBLICKEY_ECC = 0x00040001;  //导出签名公钥
    public static final int CMD_EXPORTENCPUBLICKEY_ECC = 0x00040001;   //导出加密公钥
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

    public static final int CMD_EXTERNALENCRYPT_ECC = 0x00080005;   //SM2内部加密
    public static final int CMD_EXTERNALDECRYPT_ECC = 0x00080006;

    public static final int CMD_CALCULATEMAC = 0x00100003;


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


    public static final int CMD_GENERATEKEYWITHIPK_RSA = 0x00040003;
    public static final int CMD_GENERATEKEYWITHEPK_RSA = 0x00040003;
    public static final int CMD_IMPORTKEYWITHISK_RSA = 0x00040004;


    public static final int CMD_GENERATEKEYWITHIPK_ECC = 0x00040003;
    public static final int CMD_GENERATEKEYWITHEPK_ECC = 0x00040003;
    public static final int CMD_IMPORTKEYWITHISK_ECC = 0x00040004;
    public static final int CMD_EXCHANGEDIGITENVELOPEBASEONECC = 0x00040005;
    public static final int CMD_GENERATEAGREEMENTDATAWITHECC = 0x00040006;
    public static final int CMD_GENERATEAGREEMENTDATAANDKEYWITHECC = 0x00040006;
    public static final int CMD_GENERATEKEYWITHECC = 0x00040006;


    public static final int CMD_DESTROYKEY = 0x0004000a;
    public static final int CMD_GENERATEKEYWITHKEK = 0x0004000b;
    public static final int CMD_IMPORTKEYWITHKEK = 0x0004000c;


    public static final int CMD_CREATEFILE = 0x00400001;
    public static final int CMD_READFILE = 0x00400002;
    public static final int CMD_WRITEFILE = 0x00400003;
    public static final int CMD_DELETEFILE = 0x00400004;

    // USBKEY 控制模式管理接口
    public static final int CMD_INITDEVICE = 0x01020001;
    public static final int CMD_ADDUSER = 0x01020002;
    public static final int CMD_GETCURRENTSTATUS = 0x01020003;
    public static final int CMD_PROTOCOLSTART = 0x01020004;
    public static final int CMD_PROTOCOLEND = 0x01020005;
    public static final int CMD_LOGOUTUKEY = 0x01020006;
    public static final int CMD_DELUKEY = 0x01020007;
    public static final int CMD_GETKEYSTATUS = 0x01020008;
    public static final int CMD_BACKUPINIT = 0x01020009;
    public static final int CMD_BACKUPEXPORTKEYCOMPONENT = 0x0102000a;
    public static final int CMD_BACKUPEXPORTMANAGEMENTINFO = 0x0102000b;
    public static final int CMD_BACKUPEXPORTRSAKEY = 0x0102000c;
    public static final int CMD_BACKUPEXPORTECCKEY = 0x0102000d;
    public static final int CMD_BACKUPEXPORTKEK = 0x0102000e;
    public static final int CMD_BACKUPFINAL = 0x0102000f;
    public static final int CMD_RESTOREINIT = 0x01020010;
    public static final int CMD_EXPORTPUBLICKEYECC = 0x01020011;
    public static final int CMD_RESTOREIMPORTKEYCOMPONENT = 0x01020012;
    public static final int CMD_RESTOREIMPORTMANAGEMENTINFO = 0x01020013;
    public static final int CMD_RESTOREOMPORTRSAKEY = 0x01020014;
    public static final int CMD_RESTOREIMPORTECCKEY = 0x01020015;
    public static final int CMD_RESTOREOMPORTKEK = 0x01020016;
    public static final int CMD_RESTOREFINAL = 0x01020017;
    public static final int CMD_GENERATEKEK = 0x01020018;
    public static final int CMD_INPUTKEK = 0x01020019;
    public static final int CMD_DELETEKEK = 0x0102001a;
    public static final int CMD_GENERATERSAKEYPAIR = 0x0102001b;
    public static final int CMD_INPUTRSAKEYPAIR = 0x0102001c;
    public static final int CMD_DESTROYRSAKEYPAIR = 0x0102001d;
    public static final int CMD_GENERATEECCKEYPAIR = 0x0102001e;
    public static final int CMD_IMPORTECCKEYPAIR = 0x0102001f;
    public static final int CMD_DESTROYECCKEYPAIR = 0x01020020;
    public static final int CMD_SETPRIVATEKEYACCESSPWD = 0x01020021;
    public static final int CMD_GETDEVICERUNSTATUS = 0x01020022;
    public static final int CMD_STARTSERVER = 0x01020023;
    public static final int CMD_STOPSERVER = 0x01020024;
    public static final int CMD_WRITELOGFILE = 0x01020025;
    public static final int CMD_GETLOGFILESTATUS = 0x01020026;
    public static final int CMD_READLOGFILE = 0x01020027;
    public static final int CMD_GETWHITELIST = 0x01020028;
    public static final int CMD_ADDWHITELIST = 0x01020029;
    public static final int CMD_DELETEWHITELIST = 0x0102002a;
    public static final int CMD_SENDLOCALKEYAGREEMENTPUBLICKEYCIPHERTEXT = 0x0102002b;
    public static final int CMD_GENERATENEGOTIATIONKEY = 0x0102002c;
    public static final int CMD_CHECKKEYMANAGER = 0x0102002d;
    public static final int CMD_CHECKKEYOPERATOR = 0x0102002e;
    public static final int CMD_SENDANDRECEIVEDATA = 0x01020080;

    public static final int CMD_ADDONEMANAGER = 0x01020101;
    public static final int CMD_DELONEMANAGER = 0x01020102;
    public static final int CMD_ADDONEOPERATER = 0x01020103;
    public static final int CMD_DELONEOPERATER = 0x01020104;
    public static final int CMD_ADDONEACCENDANT = 0x01020105;
    public static final int CMD_DELONEACCENDANT = 0x01020106;
    public static final int CMD_CHANGEPIN = 0x01020107;

    public static final int CMD_USER_LOGIN = 0x00010001;
    public static final int CMD_ADD_CA_CERT = 0x00010002;
    public static final int CMD_GET_CERT_COUNT = 0x00010003;
    public static final int CMD_GET_ALL_ALT_NAME = 0x00010004;
    public static final int CMD_GET_CERT = 0x00010005;
    public static final int CMD_DELETE_CERT = 0x00010006;
    public static final int CMD_VERIFY_CERT = 0x00010007;
    public static final int CMD_VERIFY_CERT_BY_CRL = 0x00010008;
    public static final int CMD_GET_CERT_INFO = 0x00010009;
    public static final int CMD_GET_CERT_EXT_TYPE_INFO = 0x0001000A;
    public static final int CMD_GET_SERVER_CERT_INFO = 0x0001000B;
    public static final int CMD_GET_INSTANCE = 0x0001000C;
    public static final int CMD_GET_CA_CERT_ALTNAME = 0x0001000D;
    public static final int CMD_GET_CERT_BY_POLICY_NAME = 0x0001000F;
    public static final int CMD_SM2_SIGNDATA_ENCODE = 0x00010821;
    public static final int CMD_SM2_SIGNDATA_DECODE = 0x00010822;
    public static final int CMD_SM2_SIGNDATA_VERIFY = 0x00010823;
}
