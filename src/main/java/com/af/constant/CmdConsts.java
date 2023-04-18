package com.af.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 17:53
 */
public enum CmdConsts {
    ;
    static final int CMD_ENCRYPT = 0x00100001;
    static final int CMD_DECRYPT = 0x00100002;

    static final int CMD_DEVICEINFO = 0x00020001;
    static final int CMD_GENERATERANDOM = 0x00020002;

    static final int CMD_EXPORTSIGNPUBLICKEY_RSA = 0x00040001;
    static final int CMD_EXPORTENCPUBLICKEY_RSA = 0x00040001;
    static final int CMD_GENERATEKEYPAIR_RSA = 0x00040002;
    static final int CMD_GENERATEKEYWITHIPK_RSA = 0x00040003;
    static final int CMD_GENERATEKEYWITHEPK_RSA = 0x00040003;
    static final int CMD_IMPORTKEYWITHISK_RSA = 0x00040004;
    static final int CMD_EXCHANGEDIGITENVELOPEBASEONRSA = 0x00040005;

    static final int CMD_EXPORTSIGNPUBLICKEY_ECC = 0x00040001;
    static final int CMD_EXPORTENCPUBLICKEY_ECC = 0x00040001;
    static final int CMD_GENERATEKEYPAIR_ECC = 0x00040002;
    static final int CMD_GENERATEKEYWITHIPK_ECC = 0x00040003;
    static final int CMD_GENERATEKEYWITHEPK_ECC = 0x00040003;
    static final int CMD_IMPORTKEYWITHISK_ECC = 0x00040004;
    static final int CMD_EXCHANGEDIGITENVELOPEBASEONECC = 0x00040005;
    static final int CMD_GENERATEAGREEMENTDATAWITHECC = 0x00040006;
    static final int CMD_GENERATEAGREEMENTDATAANDKEYWITHECC = 0x00040006;
    static final int CMD_GENERATEKEYWITHECC = 0x00040006;

    static final int CMD_GETPRIVATEKEYACCESSRIGHT = 0x00040007;

    static final int CMD_DESTROYKEY = 0x0004000a;
    static final int CMD_GENERATEKEYWITHKEK = 0x0004000b;
    static final int CMD_IMPORTKEYWITHKEK = 0x0004000c;

    static final int CMD_EXTERNALPUBLICKEYOPERATION_RSA = 0x00080001;
    static final int CMD_EXTERNALPRIVATEKEYOPERATION_RSA = 0x00080002;

    static final int CMD_INTERNALPUBLICKEYOPERATION_RSA = 0x00080001;
    static final int CMD_INTERNALPRIVATEKEYOPERATION_RSA = 0x00080002;

    static final int CMD_EXTERNALSIGN_ECC = 0x00080003;
    static final int CMD_EXTERNALVERIFY_ECC = 0x00080004;

    static final int CMD_INTERNALSIGN_ECC = 0x00080003;
    static final int CMD_INTERNALVERIFY_ECC = 0x00080004;

    static final int CMD_EXTERNALENCRYPT_ECC = 0x00080005;
    static final int CMD_EXTERNALDECRYPT_ECC = 0x00080006;

    static final int CMD_CALCULATEMAC = 0x00100003;

    static final int CMD_CREATEFILE = 0x00400001;
    static final int CMD_READFILE = 0x00400002;
    static final int CMD_WRITEFILE = 0x00400003;
    static final int CMD_DELETEFILE = 0x00400004;
    static final int CMD_EXPORT_KEY = 0x00400005;
    static final int CMD_INPUT_KEK = 0x01020019;
    static final int CMD_DELETE_KEK = 0x0102001a;
    static final int CMD_SEND_LOCAL_KEY_AGREEMENT_PUBLIC_KEY_CIPHER_TEXT = 0x0102002b;
    static final int CMD_GENERATE_NEGOTIATION_KEY = 0x0102002c;
    static final int CMD_GET_KEY_STATUS = 0x01020008;

    // USBKEY 控制模式管理接口
    static final int CMD_INITDEVICE = 0x01020001;
    static final int CMD_ADDUSER = 0x01020002;
    static final int CMD_GETCURRENTSTATUS = 0x01020003;
    static final int CMD_PROTOCOLSTART = 0x01020004;
    static final int CMD_PROTOCOLEND = 0x01020005;
    static final int CMD_LOGOUTUKEY = 0x01020006;
    static final int CMD_DELUKEY = 0x01020007;
    static final int CMD_GETKEYSTATUS = 0x01020008;
    static final int CMD_BACKUPINIT = 0x01020009;
    static final int CMD_BACKUPEXPORTKEYCOMPONENT = 0x0102000a;
    static final int CMD_BACKUPEXPORTMANAGEMENTINFO = 0x0102000b;
    static final int CMD_BACKUPEXPORTRSAKEY = 0x0102000c;
    static final int CMD_BACKUPEXPORTECCKEY = 0x0102000d;
    static final int CMD_BACKUPEXPORTKEK = 0x0102000e;
    static final int CMD_BACKUPFINAL = 0x0102000f;
    static final int CMD_RESTOREINIT = 0x01020010;
    static final int CMD_EXPORTPUBLICKEYECC = 0x01020011;
    static final int CMD_RESTOREIMPORTKEYCOMPONENT = 0x01020012;
    static final int CMD_RESTOREIMPORTMANAGEMENTINFO = 0x01020013;
    static final int CMD_RESTOREOMPORTRSAKEY = 0x01020014;
    static final int CMD_RESTOREIMPORTECCKEY = 0x01020015;
    static final int CMD_RESTOREOMPORTKEK = 0x01020016;
    static final int CMD_RESTOREFINAL = 0x01020017;
    static final int CMD_GENERATEKEK = 0x01020018;
    static final int CMD_INPUTKEK = 0x01020019;
    static final int CMD_DELETEKEK = 0x0102001a;
    static final int CMD_GENERATERSAKEYPAIR = 0x0102001b;
    static final int CMD_INPUTRSAKEYPAIR = 0x0102001c;
    static final int CMD_DESTROYRSAKEYPAIR = 0x0102001d;
    static final int CMD_GENERATEECCKEYPAIR = 0x0102001e;
    static final int CMD_IMPORTECCKEYPAIR = 0x0102001f;
    static final int CMD_DESTROYECCKEYPAIR = 0x01020020;
    static final int CMD_SETPRIVATEKEYACCESSPWD = 0x01020021;
    static final int CMD_GETDEVICERUNSTATUS = 0x01020022;
    static final int CMD_STARTSERVER = 0x01020023;
    static final int CMD_STOPSERVER = 0x01020024;
    static final int CMD_WRITELOGFILE = 0x01020025;
    static final int CMD_GETLOGFILESTATUS = 0x01020026;
    static final int CMD_READLOGFILE = 0x01020027;
    static final int CMD_GETWHITELIST = 0x01020028;
    static final int CMD_ADDWHITELIST = 0x01020029;
    static final int CMD_DELETEWHITELIST = 0x0102002a;
    static final int CMD_SENDLOCALKEYAGREEMENTPUBLICKEYCIPHERTEXT = 0x0102002b;
    static final int CMD_GENERATENEGOTIATIONKEY = 0x0102002c;
    static final int CMD_CHECKKEYMANAGER = 0x0102002d;
    static final int CMD_CHECKKEYOPERATOR = 0x0102002e;
    static final int CMD_SENDANDRECEIVEDATA = 0x01020080;

    static final int CMD_LOGIN = 0x01020100;
    static final int CMD_ADDONEMANAGER = 0x01020101;
    static final int CMD_DELONEMANAGER = 0x01020102;
    static final int CMD_ADDONEOPERATER = 0x01020103;
    static final int CMD_DELONEOPERATER = 0x01020104;
    static final int CMD_ADDONEACCENDANT = 0x01020105;
    static final int CMD_DELONEACCENDANT = 0x01020106;
    static final int CMD_CHANGEPIN = 0x01020107;

    static final int CMD_GENERATE_RANDOM = 0x00020002;
    static final int CMD_GENERATE_KEY_PAIR_RSA = 0x00040002;
    static final int CMD_GENERATE_KEY_PAIR_SM2 = 0x00040002;
    static final int CMD_GET_PRIVATE_KEY_ACCESS_RIGHT = 0x00040007;

}
