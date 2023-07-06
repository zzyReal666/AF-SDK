package com.szaf.struct.impl.sm1;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/6 15:20
 */
@Getter
@AllArgsConstructor
public class SM1CBCData {
    private byte[] outData;
    private byte[] IV;
}
