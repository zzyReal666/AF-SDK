package com.af.socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 16:06
 */
public class AFHsmSession {
    private static final Logger logger = LoggerFactory.getLogger(AFHsmSession.class);

    private AFHsmSocket[] sockets;
    private int hsmSocketIndex;
    private int maxSocketCount;
}
