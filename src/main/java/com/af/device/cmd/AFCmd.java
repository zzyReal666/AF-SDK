package com.af.device.cmd;

import com.af.netty.NettyClient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description Cmd 父类
 * @since 2023/5/29 11:16
 */
@Getter
@Setter
@AllArgsConstructor
public class AFCmd {
    public final Logger logger = LoggerFactory.getLogger(this.getClass());
    public final NettyClient client;
    public byte[] agKey;

}
