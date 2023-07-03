package com.af.nettyNew;

import com.af.constant.SpecialRequestsType;
import io.netty.channel.Channel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 通道映射
 * @since 2023/6/30 17:36
 */
@Getter
@Setter
@ToString
@AllArgsConstructor
public class ChannelMapping {

    private Channel channel;
    private boolean isUsed;
    private SpecialRequestsType type;
}
