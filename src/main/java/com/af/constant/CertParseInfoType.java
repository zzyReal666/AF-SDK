package com.af.constant;

import java.nio.charset.StandardCharsets;

public class CertParseInfoType {
    /* 证书解析项标识 */
    public static int SGD_CERT_VERSION = 0x00000001; ///< 证书版本
    public static int SGD_CERT_SERIAL = 0x00000002; ///< 证书序列号
    public static int SGD_CERT_ISSUER = 0x00000005; ///< 证书颁发者信息
    public static int SGD_CERT_VALID_TIME = 0x00000006; ///< 证书有效期
    public static int SGD_CERT_SUBJECT = 0x00000007; ///< 证书拥有者信息
    public static int SGD_CERT_DER_PUBLIC_KEY = 0x00000008; ///< 证书公钥信息
    public static int SGD_CERT_DER_EXTENSIONS = 0x00000009; ///< 证书扩展项信息

    public static int SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO = 0x00000011; ///< 颁发者秘钥标识符
    public static int SGD_EXT_SUBJECTKEYIDENTIFIER_INFO = 0x00000012; ///< 证书持有者秘钥标识符
    public static int SGD_EXT_KEYUSAGE_INFO = 0x00000013; ///< 秘钥用途
    public static int SGD_EXT_PRIVATEKEYYSAGEPERIOD_INFO = 0x00000014; ///< 私钥有效期
    public static int SGD_EXT_CERTIFICATEPOLICIES_INFO = 0x00000015; ///< 证书策略
    public static int SGD_EXT_POLICYMAPPINGS_INFO = 0x00000016; ///< 策略映射
    public static int SGD_EXT_BASICCONSTRAINTS_INFO = 0x00000017; ///< 基本限制
    public static int SGD_EXT_POLICYCONSTRAINTS_INFO = 0x00000018; ///< 策略限制
    public static int SGD_EXT_EXTKEYUSAGE_INFO = 0x00000019; ///< 扩展秘钥用途
    public static int SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO = 0x0000001A; ///< CRL发布点
    public static int SGD_EXT_NETSCAPE_CERT_TYPE_INFO = 0x0000001B; ///< Netscape属性
    public static int SGD_EXT_SELFDEFINED_EXTENSION_INFO = 0x0000001C; ///< 私有的自定义扩展项

    public static int SGD_CERT_ISSUER_CN = 0x00000021; ///< 证书颁发者CN
    public static int SGD_CERT_ISSUER_O = 0x00000022; ///< 证书颁发者O
    public static int SGD_CERT_ISSUER_OU = 0x00000023; ///< 证书颁发者OU

    public static int SGD_CERT_SUBJECT_CN = 0x00000031; ///< 证书拥有者信息CN
    public static int SGD_CERT_SUBJECT_O = 0x00000032; ///< 证书拥有者信息O
    public static int SGD_CERT_SUBJECT_OU = 0x00000033; ///< 证书拥有者信息OU
    public static int SGD_CERT_SUBJECT_EMAIL = 0x00000034; ///< 证书拥有者信息EMail
    public static int SGD_CERT_NOTBEFORE_TIME = 0x00000035; ///< 证书起始日期
    public static int SGD_CERT_NOTAFTER_TIME = 0x00000036; ///< 证书截止日期

    /* 证书的其他解析项目 */
    public static int SGD_CERT_SIGNATURE_ALG = 0x00000100; ///< 证书签名算法
    public static int SGD_CERT_PUBKEY_ALG = 0x00000101; ///< 证书公钥算法

    /* 扩展OID */
    public static byte[] Subject_Directory_Attributes = "2.5.29.9".getBytes(StandardCharsets.UTF_8);

    public static byte[] Subject_Key_Identifier = "2.5.29.14".getBytes(StandardCharsets.UTF_8);

    public static byte[] Key_Usage = "2.5.29.15".getBytes(StandardCharsets.UTF_8);

    public static byte[] Private_Key_Usage_Period = "2.5.29.16".getBytes(StandardCharsets.UTF_8);

    public static byte[] Subject_Alternative_Name = "2.5.29.17".getBytes(StandardCharsets.UTF_8);

    public static byte[] Issuer_Alternative_Name = "2.5.29.18".getBytes(StandardCharsets.UTF_8);

    public static byte[] Basic_Constraints = "2.5.29.19".getBytes(StandardCharsets.UTF_8);

    public static byte[] CRL_Number = "2.5.29.20".getBytes(StandardCharsets.UTF_8);

    public static byte[] Reason_code = "2.5.29.21".getBytes(StandardCharsets.UTF_8);

    public static byte[] Hold_Instruction_Code = "2.5.29.23".getBytes(StandardCharsets.UTF_8);

    public static byte[] Invalidity_Date = "2.5.29.24".getBytes(StandardCharsets.UTF_8);

    public static byte[] Delta_CRL_indicator = "2.5.29.27".getBytes(StandardCharsets.UTF_8);

    public static byte[] Issuing_Distribution_Point = "2.5.29.28".getBytes(StandardCharsets.UTF_8);

    public static byte[] Certificate_Issuer = "2.5.29.29".getBytes(StandardCharsets.UTF_8);

    public static byte[] Name_Constraints = "2.5.29.30".getBytes(StandardCharsets.UTF_8);

    public static byte[] CRL_Distribution_Points = "2.5.29.31".getBytes(StandardCharsets.UTF_8);

    public static byte[] Certificate_Policies = "2.5.29.32".getBytes(StandardCharsets.UTF_8);

    public static byte[] Policy_Mappings = "2.5.29.33".getBytes(StandardCharsets.UTF_8);

    public static byte[] Authority_Key_Identifier = "2.5.29.35".getBytes(StandardCharsets.UTF_8);

    public static byte[] Policy_Constraints = "2.5.29.36".getBytes(StandardCharsets.UTF_8);

    public static byte[] Extended_Key_Usage = "2.5.29.37".getBytes(StandardCharsets.UTF_8);

    public static byte[] Freshest_CRL = "2.5.29.46".getBytes(StandardCharsets.UTF_8);

    public static byte[] Inhibit_Any_Policy = "2.5.29.54".getBytes(StandardCharsets.UTF_8);

    public static byte[] Authority_Info_Access = "1.3.6.1.5.5.7.1.1".getBytes(StandardCharsets.UTF_8);

    public static byte[] Subject_Info_Access = "1.3.6.1.5.5.7.1.11".getBytes(StandardCharsets.UTF_8);

    public static byte[] Logo_Type = "1.3.6.1.5.5.7.1.12".getBytes(StandardCharsets.UTF_8);

    public static byte[] BiometricInfo = "1.3.6.1.5.5.7.1.2".getBytes(StandardCharsets.UTF_8);

    public static byte[] QCStatements = "1.3.6.1.5.5.7.1.3".getBytes(StandardCharsets.UTF_8);

    public static byte[] Audit_identity_extension_in_attribute_certificates = "1.3.6.1.5.5.7.1.4".getBytes(StandardCharsets.UTF_8);

    public static byte[] NoRevAvail_extension_in_attribute_certificates = "2.5.29.56".getBytes(StandardCharsets.UTF_8);

    public static byte[] TargetInformation_extension_in_attribute_certificates = "2.5.29.55".getBytes(StandardCharsets.UTF_8);
}
