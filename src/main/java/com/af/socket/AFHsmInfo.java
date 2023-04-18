package com.af.socket;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description hsm的信息
 * @since 2023/4/18 10:18
 */
@Data // 生成get set方法
@AllArgsConstructor // 生成全参构造方法
@NoArgsConstructor// 生成无参构造方法
public class AFHsmInfo {
    private String ip;
    private int port;
    private String password;
}
