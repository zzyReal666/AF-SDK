package com.szaf.crypto.key.symmetricKey;

import cn.hutool.core.util.HexUtil;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 会话密钥
 * @since 2023/6/6 11:57
 */
@Getter
@Setter
@NoArgsConstructor
//@ToString
public class SessionKey {
    //会话密钥id
    private int id;
    //会话密钥长度 字节数
    private int length;
    //会话密钥
    private byte[] key;

    /**
     * toString方法  key 16进制字符串
     */
    @Override
    public String toString() {
        //id转为byte[]  hutool

        return "SessionKey{" +
                "id=" + Integer.toHexString(id) +
                ", length=" + length +
                ", key=" + HexUtil.encodeHexStr(null == key ? new byte[0] : key) +
                '}';
    }
}
