package com.af.constant;

import lombok.NoArgsConstructor;

import java.util.HashMap;

@NoArgsConstructor
public class ErrorNumber {


    /**
     * 返回的错误码转为错误信息
     * @param RetCode 错误码
     * @return
     */
    public static final String toErrorInfo(int RetCode) {
        return err.containsKey(new Integer(RetCode)) ?
                err.get(new Integer(RetCode)) + "[" + toHexString(RetCode) + "]"
                : err.get(SDR_UNKNOWERR) + "[" + toHexString(RetCode) + "]";
    }

    private static  String toHexString(int n) {
        String code = Integer.toHexString(n);

        for (int i = code.length(); i < 8; ++i) {
            code = "0" + code;
        }

        return "0x" + code;
    }

    private static class Error extends HashMap {
        private Error() {}

        public String get(int key) {
            return (String) super.get(new Integer(key));
        }

        public Object put(int key, String value) {
            return super.put(new Integer(key), value);
        }
    }

    private static Error err;

    public static int SDR_OK = 0x0;                           /*成功*/
    public static int SDR_BASE = 0x01000000;
    public static int SDR_UNKNOWERR = (SDR_BASE + 0x00000001);       /*未知错误*/
    public static int SDR_NOTSUPPORT = (SDR_BASE + 0x00000002);       /*不支持*/
    public static int SDR_COMMFAIL = (SDR_BASE + 0x00000003);    /*通信错误*/
    public static int SDR_HARDFAIL = (SDR_BASE + 0x00000004);    /*硬件错误*/
    public static int SDR_OPENDEVICE = (SDR_BASE + 0x00000005);    /*打开设备错误*/
    public static int SDR_OPENSESSION = (SDR_BASE + 0x00000006);    /*打开会话句柄错误*/
    public static int SDR_PARDENY = (SDR_BASE + 0x00000007);    /*权限不满足*/
    public static int SDR_KEYNOTEXIST = (SDR_BASE + 0x00000008);    /*密钥不存在*/
    public static int SDR_ALGNOTSUPPORT = (SDR_BASE + 0x00000009);    /*不支持的算法*/
    public static int SDR_ALGMODNOTSUPPORT = (SDR_BASE + 0x0000000A);    /*不支持的算法模式*/
    public static int SDR_PKOPERR = (SDR_BASE + 0x0000000B);    /*公钥运算错误*/
    public static int SDR_SKOPERR = (SDR_BASE + 0x0000000C);    /*私钥运算错误*/
    public static int SDR_SIGNERR = (SDR_BASE + 0x0000000D);    /*签名错误*/
    public static int SDR_VERIFYERR = (SDR_BASE + 0x0000000E);    /*验证错误*/
    public static int SDR_SYMOPERR = (SDR_BASE + 0x0000000F);    /*对称运算错误*/
    public static int SDR_STEPERR = (SDR_BASE + 0x00000010);    /*步骤错误*/
    public static int SDR_FILESIZEERR = (SDR_BASE + 0x00000011);    /*文件大小错误或输入数据长度非法*/
    public static int SDR_FILENOEXIST = (SDR_BASE + 0x00000012);    /*文件不存在*/
    public static int SDR_FILEOFSERR = (SDR_BASE + 0x00000013);    /*文件操作偏移量错误*/
    public static int SDR_KEYTYPEERR = (SDR_BASE + 0x00000014);    /*密钥类型错误*/
    public static int SDR_KEYERR = (SDR_BASE + 0x00000015);    /*密钥错误*/

    /*============================================================*/
    /*扩展错误码*/
    public static int SWR_BASE = (SDR_BASE + 0x00010000);    /*自定义错误码基础值*/
    public static int SWR_INVALID_USER = (SWR_BASE + 0x00000001);    /*无效的用户名*/
    public static int SWR_INVALID_AUTHENCODE = (SWR_BASE + 0x00000002);    /*无效的授权码*/
    public static int SWR_PROTOCOL_VER_ERR = (SWR_BASE + 0x00000003);    /*不支持的协议版本*/
    public static int SWR_INVALID_COMMAND = (SWR_BASE + 0x00000004);    /*错误的命令字*/
    public static int SWR_INVALID_PARAMETERS = (SWR_BASE + 0x00000005);    /*参数错误或错误的数据包格式*/
    public static int SWR_FILE_ALREADY_EXIST = (SWR_BASE + 0x00000006);    /*已存在同名文件*/
    public static int SWR_SYNCH_ERR = (SWR_BASE + 0x00000007);    /*多卡同步错误*/
    public static int SWR_SYNCH_LOGIN_ERR = (SWR_BASE + 0x00000008);    /*多卡同步后登录错误*/

    public static int SWR_SOCKET_TIMEOUT = (SWR_BASE + 0x00000100);    /*超时错误*/
    public static int SWR_CONNECT_ERR = (SWR_BASE + 0x00000101);    /*连接服务器错误*/
    public static int SWR_SET_SOCKOPT_ERR = (SWR_BASE + 0x00000102);    /*设置Socket参数错误*/
    public static int SWR_SOCKET_SEND_ERR = (SWR_BASE + 0x00000104);    /*发送LOGINRequest错误*/
    public static int SWR_SOCKET_RECV_ERR = (SWR_BASE + 0x00000105);    /*发送LOGINRequest错误*/
    public static int SWR_SOCKET_RECV_0 = (SWR_BASE + 0x00000106);    /*发送LOGINRequest错误*/

    public static int SWR_SEM_TIMEOUT = (SWR_BASE + 0x00000200);    /*超时错误*/
    public static int SWR_NO_AVAILABLE_HSM = (SWR_BASE + 0x00000201);    /*没有可用的加密机*/
    public static int SWR_NO_AVAILABLE_CSM = (SWR_BASE + 0x00000202);    /*加密机内没有可用的加密模块*/

    public static int SWR_CONFIG_ERR = (SWR_BASE + 0x00000301);    /*配置文件错误*/

    public static int SWR_MALLOC_ERR = (SWR_BASE + 0x00000401);    /*malloc错误*/
    public static int SWR_DEVICE_NULL_ERR = (SWR_BASE + 0x00000402);    /*Device已关闭*/
    public static int SWR_DEVICE_DESCRITOR_ERR = (SWR_BASE + 0x00000403);    /*Device中fd无效*/
    public static int SWR_SESSION_NONEXIST = (SWR_BASE + 0x00000404);    /*会话不存在*/
    public static int SWR_INVALID_FILENAME = (SWR_BASE + 0x00000405);    /*文件名或文件名长度不合法*/
    public static int SWR_DRIVERCOMM_ERR = (SWR_BASE + 0x00000406);    /*与驱动通信错误*/
    public static int SWR_PRIKEYPASSWORD = (SWR_BASE + 0x00000407);    /*私钥口令字太长*/

    /*============================================================*/
    /*密码卡错误码*/
    public static int SWR_CARD_BASE = (SDR_BASE + 0x00020000);            /*密码卡错误码*/
    public static int SWR_CARD_UNKNOWERR = (SWR_CARD_BASE + 0x00000001);    //未知错误
    public static int SWR_CARD_NOTSUPPORT = (SWR_CARD_BASE + 0x00000002);    //不支持的接口调用
    public static int SWR_CARD_COMMFAIL = (SWR_CARD_BASE + 0x00000003);    //与设备通信失败
    public static int SWR_CARD_HARDFAIL = (SWR_CARD_BASE + 0x00000004);    //运算模块无响应
    public static int SWR_CARD_OPENDEVICE = (SWR_CARD_BASE + 0x00000005);    //打开设备失败
    public static int SWR_CARD_OPENSESSION = (SWR_CARD_BASE + 0x00000006);    //创建会话失败
    public static int SWR_CARD_PARDENY = (SWR_CARD_BASE + 0x00000007);    //无私钥使用权限
    public static int SWR_CARD_KEYNOTEXIST = (SWR_CARD_BASE + 0x00000008);    //不存在的密钥调用
    public static int SWR_CARD_ALGNOTSUPPORT = (SWR_CARD_BASE + 0x00000009);    //不支持的算法调用
    public static int SWR_CARD_ALGMODNOTSUPPORT = (SWR_CARD_BASE + 0x00000010);    //不支持的算法调用
    public static int SWR_CARD_PKOPERR = (SWR_CARD_BASE + 0x00000011);    //公钥运算失败
    public static int SWR_CARD_SKOPERR = (SWR_CARD_BASE + 0x00000012);    //私钥运算失败
    public static int SWR_CARD_SIGNERR = (SWR_CARD_BASE + 0x00000013);    //签名运算失败
    public static int SWR_CARD_VERIFYERR = (SWR_CARD_BASE + 0x00000014);    //验证签名失败
    public static int SWR_CARD_SYMOPERR = (SWR_CARD_BASE + 0x00000015);    //对称算法运算失败
    public static int SWR_CARD_STEPERR = (SWR_CARD_BASE + 0x00000016);    //多步运算步骤错误
    public static int SWR_CARD_FILESIZEERR = (SWR_CARD_BASE + 0x00000017);    //文件长度超出限制
    public static int SWR_CARD_FILENOEXIST = (SWR_CARD_BASE + 0x00000018);    //指定的文件不存在
    public static int SWR_CARD_FILEOFSERR = (SWR_CARD_BASE + 0x00000019);    //文件起始位置错误
    public static int SWR_CARD_KEYTYPEERR = (SWR_CARD_BASE + 0x00000020);    //密钥类型错误
    public static int SWR_CARD_KEYERR = (SWR_CARD_BASE + 0x00000021);    //密钥错误
    public static int SWR_CARD_BUFFER_TOO_SMALL = (SWR_CARD_BASE + 0x00000101);    //接收参数的缓存区太小
    public static int SWR_CARD_DATA_PAD = (SWR_CARD_BASE + 0x00000102);    //数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式
    public static int SWR_CARD_DATA_SIZE = (SWR_CARD_BASE + 0x00000103);    //明文或密文长度不符合相应的算法要求
    public static int SWR_CARD_CRYPTO_NOT_INIT = (SWR_CARD_BASE + 0x00000104);    //该错误表明没有为相应的算法调用初始化函数

    //01/03/09版密码卡权限管理错误码
    public static int SWR_CARD_MANAGEMENT_DENY = (SWR_CARD_BASE + 0x00001001);    //管理权限不满足
    public static int SWR_CARD_OPERATION_DENY = (SWR_CARD_BASE + 0x00001002);    //操作权限不满足
    public static int SWR_CARD_DEVICE_STATUS_ERR = (SWR_CARD_BASE + 0x00001003);    //当前设备状态不满足现有操作
    public static int SWR_CARD_LOGIN_ERR = (SWR_CARD_BASE + 0x00001011);    //登录失败
    public static int SWR_CARD_USERID_ERR = (SWR_CARD_BASE + 0x00001012);    //用户ID数目/号码错误
    public static int SWR_CARD_PARAMENT_ERR = (SWR_CARD_BASE + 0x00001013);    //参数错误

    //05/06版密码卡权限管理错误码
    public static int SWR_CARD_MANAGEMENT_DENY_05 = (SWR_CARD_BASE + 0x00000801);    //管理权限不满足
    public static int SWR_CARD_OPERATION_DENY_05 = (SWR_CARD_BASE + 0x00000802);    //操作权限不满足
    public static int SWR_CARD_DEVICE_STATUS_ERR_05 = (SWR_CARD_BASE + 0x00000803);    //当前设备状态不满足现有操作
    public static int SWR_CARD_LOGIN_ERR_05 = (SWR_CARD_BASE + 0x00000811);    //登录失败
    public static int SWR_CARD_USERID_ERR_05 = (SWR_CARD_BASE + 0x00000812);    //用户ID数目/号码错误
    public static int SWR_CARD_PARAMENT_ERR_05 = (SWR_CARD_BASE + 0x00000813);    //参数错误

    /*============================================================*/
    /*读卡器错误*/
    public static int SWR_CARD_READER_BASE = (SDR_BASE + 0x00030000);    //	读卡器类型错误
    public static int SWR_CARD_READER_PIN_ERROR = (SWR_CARD_READER_BASE + 0x000063CE);  //口令错误
    public static int SWR_CARD_READER_NO_CARD = (SWR_CARD_READER_BASE + 0x0000FF01);     //	IC未插入
    public static int SWR_CARD_READER_CARD_INSERT = (SWR_CARD_READER_BASE + 0x0000FF02);     //	IC插入方向错误或不到位
    public static int SWR_CARD_READER_CARD_INSERT_TYPE = (SWR_CARD_READER_BASE + 0x0000FF03);     //	IC类型错误

    public static int SWR_ANF_BASE = (SDR_BASE + 0x00040000);
    public static int SWR_ANF_GETRANDOM = (SWR_ANF_BASE + 0x00000001);
    public static int SWR_ANF_IO = (SWR_ANF_BASE + 0x00000002);
    public static int SWR_ANF_CARD_SM3 = (SWR_ANF_BASE + 0x00000003);
    public static int SWR_ANF_CARD_SM2_D = (SWR_ANF_BASE + 0x00000004);
    public static int SWR_ANF_CARD_SM2_XY = (SWR_ANF_BASE + 0x00000005);
    public static int SWR_ANF_INFO = (SWR_ANF_BASE + 0x00000006);

    public static int SWR_ANF_MANAGE_BASE = (SDR_BASE + 0x00041000);
    public static int SWR_ANF_CARD_INIT = (SWR_ANF_MANAGE_BASE + 0x00000001);
    public static int SWR_ANF_PERMISSIONS_GET = (SWR_ANF_MANAGE_BASE + 0x00000002);
    public static int SWR_ANF_MANAGE_EXIST = (SWR_ANF_MANAGE_BASE + 0x00000003);
    public static int SWR_ANF_MANAGE_NONEXIST = (SWR_ANF_MANAGE_BASE + 0x00000004);
    public static int SWR_ANF_PERMISSIONS_UNSATISFIED = (SWR_ANF_MANAGE_BASE + 0x00000005);
    public static int SWR_ANF_OPERATOR_EXIST = (SWR_ANF_MANAGE_BASE + 0x00000006);
    public static int SWR_ANF_OPERATOR_NONEXIST = (SWR_ANF_MANAGE_BASE + 0x00000007);
    public static int SWR_ANF_USER_NONEXIST = (SWR_ANF_MANAGE_BASE + 0x00000008);
    public static int SWR_ANF_MANAGER_ATLEASTONE = (SWR_ANF_MANAGE_BASE + 0x00000009); //at least one manager
    public static int SWR_ANF_USER_LOGGED = (SWR_ANF_MANAGE_BASE + 0x0000000a);
    public static int SWR_ANF_ACCENDANT_EXIST = (SWR_ANF_MANAGE_BASE + 0x0000000b);
    public static int SWR_ANF_ACCENDANT_NONEXIST = (SWR_ANF_MANAGE_BASE + 0x0000000c);

    public static int SWR_ANF_UKEY_BASE = (SDR_BASE + 0x00042000);
    public static int SWR_ANF_UKEY_TYPE = (SWR_ANF_UKEY_BASE + 0x00000001);
    public static int SWR_ANF_UKEY_ID = (SWR_ANF_UKEY_BASE + 0x00000002);

    public static int SWR_ANF_CARD_RETURN_BASE = (SDR_BASE + 0x00050000);

    static {
        err = new Error();
        err.put(SDR_OK, "成功");
        err.put(SDR_UNKNOWERR, "未知错误");
        err.put(SDR_NOTSUPPORT, "不支持");
        err.put(SDR_COMMFAIL, "通信错误");
        err.put(SDR_HARDFAIL, "硬件错误");
        err.put(SDR_OPENDEVICE, "打开设备错误");
        err.put(SDR_OPENSESSION, "打开会话句柄错误");
        err.put(SDR_PARDENY, "权限不满足");
        err.put(SDR_KEYNOTEXIST, "密钥不存在");
        err.put(SDR_ALGNOTSUPPORT, "不支持的算法");
        err.put(SDR_ALGMODNOTSUPPORT, "不支持的算法模式");
        err.put(SDR_PKOPERR, "公钥运算错误");
        err.put(SDR_SKOPERR, "私钥运算错误");
        err.put(SDR_SIGNERR, "签名错误");
        err.put(SDR_VERIFYERR, "验证错误");
        err.put(SDR_SYMOPERR, "对称运算错误");
        err.put(SDR_STEPERR, "步骤错误");
        err.put(SDR_FILESIZEERR, "文件大小错误或输入数据长度非法");
        err.put(SDR_FILENOEXIST, "文件不存在");
        err.put(SDR_FILEOFSERR, "文件操作偏移量错误");
        err.put(SDR_KEYTYPEERR, "密钥类型错误");
        err.put(SDR_KEYERR, "密钥错误");
        err.put(SWR_INVALID_USER, "无效的用户名");
        err.put(SWR_INVALID_AUTHENCODE, "无效的授权码");
        err.put(SWR_PROTOCOL_VER_ERR, "不支持的协议版本");
        err.put(SWR_INVALID_COMMAND, "错误的命令字");
        err.put(SWR_INVALID_PARAMETERS, "参数错误或错误的数据包格式");
        err.put(SWR_FILE_ALREADY_EXIST, "已存在同名文件");
        err.put(SWR_SYNCH_ERR, "多卡同步错误");
        err.put(SWR_SYNCH_LOGIN_ERR, "多卡同步后登录错误");
        err.put(SWR_SOCKET_TIMEOUT, "超时错误");
        err.put(SWR_CONNECT_ERR, "连接服务器错误");
        err.put(SWR_SET_SOCKOPT_ERR, "设置Socket参数错误");
        err.put(SWR_SOCKET_SEND_ERR, "发送数据错误");
        err.put(SWR_SOCKET_RECV_ERR, "接收数据错误");
        err.put(SWR_SOCKET_RECV_0, "发送LOGINRequest错误");
        err.put(SWR_SEM_TIMEOUT, "超时错误");
        err.put(SWR_NO_AVAILABLE_HSM, "没有可用的加密机");
        err.put(SWR_NO_AVAILABLE_CSM, "加密机内没有可用的加密模块");
        err.put(SWR_CONFIG_ERR, "配置文件错误");
        err.put(SWR_MALLOC_ERR, "malloc错误");
        err.put(SWR_DEVICE_NULL_ERR, "Device已关闭");
        err.put(SWR_DEVICE_DESCRITOR_ERR, "Device中fd无效");
        err.put(SWR_SESSION_NONEXIST, "会话不存在");
        err.put(SWR_INVALID_FILENAME, "文件名或文件名长度不合法");
        err.put(SWR_DRIVERCOMM_ERR, "与驱动通信错误");
        err.put(SWR_PRIKEYPASSWORD, "私钥口令字太长");
        err.put(SWR_CARD_NOTSUPPORT, "不支持的接口调用");
        err.put(SWR_CARD_COMMFAIL, "与设备通信失败");
        err.put(SWR_CARD_HARDFAIL, "运算模块无响应");
        err.put(SWR_CARD_OPENDEVICE, "打开设备失败");
        err.put(SWR_CARD_OPENSESSION, "创建会话失败");
        err.put(SWR_CARD_PARDENY, "无私钥使用权限");
        err.put(SWR_CARD_KEYNOTEXIST, "不存在的密钥调用");
        err.put(SWR_CARD_ALGNOTSUPPORT, "不支持的算法调用");
        err.put(SWR_CARD_ALGMODNOTSUPPORT, "不支持的算法调用");
        err.put(SWR_CARD_PKOPERR, "公钥运算失败");
        err.put(SWR_CARD_SKOPERR, "私钥运算失败");
        err.put(SWR_CARD_SIGNERR, "签名运算失败");
        err.put(SWR_CARD_VERIFYERR, "验证签名失败");
        err.put(SWR_CARD_SYMOPERR, "对称算法运算失败");
        err.put(SWR_CARD_STEPERR, "多步运算步骤错误");
        err.put(SWR_CARD_FILESIZEERR, "文件长度超出限制");
        err.put(SWR_CARD_FILENOEXIST, "指定的文件不存在");
        err.put(SWR_CARD_FILEOFSERR, "文件起始位置错误");
        err.put(SWR_CARD_KEYTYPEERR, "密钥类型错误");
        err.put(SWR_CARD_KEYERR, "密钥错误");
        err.put(SWR_CARD_BUFFER_TOO_SMALL, "接收参数的缓存区太小");
        err.put(SWR_CARD_DATA_PAD, "数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式");
        err.put(SWR_CARD_DATA_SIZE, "明文或密文长度不符合相应的算法要求");
        err.put(SWR_CARD_CRYPTO_NOT_INIT, "该错误表明没有为相应的算法调用初始化函数");
        err.put(SWR_CARD_MANAGEMENT_DENY, "管理权限不满足");
        err.put(SWR_CARD_OPERATION_DENY, "操作权限不满足");
        err.put(SWR_CARD_DEVICE_STATUS_ERR, "当前设备状态不满足现有操作");
        err.put(SWR_CARD_LOGIN_ERR, "登录失败");
        err.put(SWR_CARD_USERID_ERR, "用户ID数目/号码错误");
        err.put(SWR_CARD_PARAMENT_ERR, "参数错误");
        err.put(SWR_CARD_MANAGEMENT_DENY_05, "管理权限不满足");
        err.put(SWR_CARD_OPERATION_DENY_05, "操作权限不满足");
        err.put(SWR_CARD_DEVICE_STATUS_ERR_05, "当前设备状态不满足现有操作");
        err.put(SWR_CARD_LOGIN_ERR_05, "登录失败");
        err.put(SWR_CARD_USERID_ERR_05, "用户ID数目/号码错误");
        err.put(SWR_CARD_PARAMENT_ERR_05, "参数错误");
        err.put(SWR_CARD_READER_BASE, "读卡器类型错误");
        err.put(SWR_CARD_READER_PIN_ERROR, "口令错误");
        err.put(SWR_CARD_READER_NO_CARD, "IC未插入");
        err.put(SWR_CARD_READER_CARD_INSERT, "IC插入方向错误或不到位");
        err.put(SWR_CARD_READER_CARD_INSERT_TYPE, "IC类型错误");
        err.put(SWR_ANF_GETRANDOM, "获取随机错误");
        err.put(SWR_ANF_IO, "IO错误");
        err.put(SWR_ANF_CARD_SM3, "SM3计算错误");
        err.put(SWR_ANF_CARD_SM2_D, "SM2_D错误");
        err.put(SWR_ANF_CARD_SM2_XY, "SM2_XY错误");
        err.put(SWR_ANF_INFO, "信息错误");
        err.put(SWR_ANF_CARD_INIT, "初始化错误");
        err.put(SWR_ANF_PERMISSIONS_GET, "权限获取错误");
        err.put(SWR_ANF_MANAGE_EXIST, "管理员已存在");
        err.put(SWR_ANF_MANAGE_NONEXIST, "管理员不存在");
        err.put(SWR_ANF_PERMISSIONS_UNSATISFIED, "无权限");
        err.put(SWR_ANF_OPERATOR_EXIST, "操作员已经存在");
        err.put(SWR_ANF_OPERATOR_NONEXIST, "操作员不存在");
        err.put(SWR_ANF_USER_NONEXIST, "用户不存在");
        err.put(SWR_ANF_MANAGER_ATLEASTONE, "当前管理员已是最后一个");
        err.put(SWR_ANF_USER_LOGGED, "用户已经登陆");
        err.put(SWR_ANF_ACCENDANT_EXIST, "维修员已存在");
        err.put(SWR_ANF_ACCENDANT_NONEXIST, "维修员不存在");
        err.put(SWR_ANF_UKEY_TYPE, "UKEY类型错误");
        err.put(SWR_ANF_UKEY_ID, "UKEY ID 错误");
    }


}
