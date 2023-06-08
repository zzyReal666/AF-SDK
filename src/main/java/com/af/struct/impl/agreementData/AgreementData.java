package com.af.struct.impl.agreementData;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/6/8 14:16
 */
@ToString
@Setter
@Getter
@NoArgsConstructor
public class AgreementData {

    /**
     * 会话id
     */
    private int sessionId;

    /**
     * 发起方id
     */
    private byte[] initiatorId;

    /**
     * 回复方id
     */
    private byte[] responderId;


    /**
     * 临时公钥
     */
    private byte[] tempPublicKey;

    /**
     * 公钥
     */
    private byte[] publicKey;
}
