package com.szaf.exception;

import java.util.HashMap;
import java.util.Map;

/**
 * 设备返回异常
 * 
 * @author linzhj
 * @date 2022年4月21日
 */
public class DeviceException extends RuntimeException {

    private static final long serialVersionUID = 4563934750170316524L;

    public DeviceException(Throwable e) {
        super(e.getClass().getSimpleName() + ":" + e.getMessage(), e);
    }

    public DeviceException(String message) {
        super(message);
    }

    public DeviceException(String message, Throwable throwable) {
        super(message, throwable);
    }

    /**
     * 交易时设备返回错误码
     */
    public DeviceException(String message, int errorCode) {
        super(message + ": " + getErrMessage(errorCode));
    }

    private static Map<Integer, String> errCodeMap;
    static {
        errCodeMap = new HashMap<>();
        // ---------------设备通用错误码--------------------
        errCodeMap.put(0x1021011, "通信密码错误");
        // ---------------时间戳服务器错误码--------------------
        errCodeMap.put(0x04000001, "输入的用户信息超出规定范围");
        errCodeMap.put(0x04000002, "分配给tsrequest的内存空间不够");
        errCodeMap.put(0x04000003, "找不到服务器或超时响应");
        errCodeMap.put(0x04000004, "时间戳格式错误");
        errCodeMap.put(0x04000005, "输入项目编号无效");
        errCodeMap.put(0x04000006, "签名无效");
        errCodeMap.put(0x04000007, "申请使用了不支持的算法");
        errCodeMap.put(0x04000008, "非法的申请");
        errCodeMap.put(0x04000009, "数据格式错误");
        errCodeMap.put(0x0400000A, "TSA的可信时间源出现问题");
        errCodeMap.put(0x0400000B, "不支持申请消息中声明的策略");
        errCodeMap.put(0x0400000C, "申请消息中包括了不支持的扩展");
        errCodeMap.put(0x0400000D, "有不理解或不可用的附加信息");
        errCodeMap.put(0x0400000E, "系统内部错误");
        errCodeMap.put(0x04000010, "参数错误");
        errCodeMap.put(0x04000011, "socket错误");
        errCodeMap.put(0x04000012, "配置文件错误");
        errCodeMap.put(0x04000013, "连接超时");
        errCodeMap.put(0x04000014, "申请内存失败");
        errCodeMap.put(0x04000015, "范围值空间不足");
    }

    private static String getErrMessage(int errCode) {
        if (!errCodeMap.containsKey(errCode)) {
            return "(0x" + Integer.toHexString(errCode) + ") 未知错误";
        }
        return "(0x" + Integer.toHexString(errCode) + ") " + errCodeMap.get(errCode);
    }

}
