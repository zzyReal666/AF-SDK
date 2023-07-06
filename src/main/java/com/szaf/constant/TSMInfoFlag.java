package com.szaf.constant;

import lombok.Getter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description  获取时间戳信息标识
 * @since 2023/6/8 14:59
 */
@Getter
public enum TSMInfoFlag {
    //1 STF_TIME_OF_STAMP 0x00000001 签发时间
    //2 STF_CN_OF_TSSIGNER 0x00000002 签发者的通用名
    //3 STF_ORINGINAL_DATA 0x00000003 时间戳请求的原始信息
    //4 STF_CERT_OF_TSSERVER 0x00000004 时间戳服务器的证书
    //5 STF_CERTCHAIN_OF_TSSERVER 0x00000005 时间戳服务器的证书链
    //6 STF_SOURCE_OF_TIME 0x00000006 时间源的来源
    //7 STF_TIME_PRECISION 0x00000007 时间精度
    //8 STF_RESPONSE_TYPE 0x00000008 响应方式
    //9 STF_SUBJECT_COUNTRY_OF_TSSIGNER 0x00000009 签发者国家
    //10 STF_SUBJECT_ORGNIZATION_OF_TSSIGNER 0x0000000A 签发者组织
    //11 STF_SUBJECT_CITY_OF_TSSIGNER 0x0000000B 签发者城市
    //12 STF_SUBJECT_EMAIL_OF_TSSIGNER 0x0000000C 签发者联系用电子邮箱

    STF_TIME_OF_STAMP("签发时间", 0x00000001),
    STF_CN_OF_TSSIGNER("签发者的通用名", 0x00000002),
    STF_ORINGINAL_DATA("时间戳请求的原始信息", 0x00000003),
    STF_CERT_OF_TSSERVER("时间戳服务器的证书", 0x00000004),
    STF_CERTCHAIN_OF_TSSERVER("时间戳服务器的证书链", 0x00000005),
    STF_SOURCE_OF_TIME("时间源的来源", 0x00000006),
    STF_TIME_PRECISION("时间精度", 0x00000007),
    STF_RESPONSE_TYPE("响应方式", 0x00000008),
    STF_SUBJECT_COUNTRY_OF_TSSIGNER("签发者国家", 0x00000009),
    STF_SUBJECT_ORGNIZATION_OF_TSSIGNER("签发者组织", 0x0000000A),
    STF_SUBJECT_CITY_OF_TSSIGNER("签发者城市", 0x0000000B),
    STF_SUBJECT_EMAIL_OF_TSSIGNER("签发者联系用电子邮箱", 0x0000000C);

    private String name;
    private int value;

    TSMInfoFlag(String name, int value) {
        this.name = name;
        this.value = value;
    }

}
