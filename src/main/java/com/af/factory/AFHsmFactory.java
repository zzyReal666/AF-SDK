package com.af.factory;

import com.af.config.AFProFile;
import com.af.device.IAfDevice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 10:48
 */
public class AFHsmFactory {
    private static final Logger logger = LoggerFactory.getLogger(AFHsmFactory.class);

    private static IAfDevice instance;
    private static AFProFile profile;

}
