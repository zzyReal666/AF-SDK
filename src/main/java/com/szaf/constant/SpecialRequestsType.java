package com.szaf.constant;

  /**
 * @author zhangzhongyuan@szanfu.cn
 * @description   一些特殊的请求类型  会话密钥生成和释放需要同一条通道   Hash需要同一条通道  生成协商数据需要统一条通道 MAC需要统一条通道
 * @since 2023/6/30 17:19
 */
public enum SpecialRequestsType {
    SessionKey,
    Hash,
    NegotiationData,
    MAC
}
