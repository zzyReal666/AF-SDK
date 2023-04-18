package com.af.config;

import java.util.logging.Logger;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description  配置文件读取
 * @since 2023/4/17 16:57
 */
public class AFProFile {

    public static final int LOGSIZE = 100000000;
    public static final int LOGCOUNT = 10;
    public static int MAX_HSM_COUNT = 10;
    public static int DEFAULT_CONN_PORT = 8008;
    public static String DEFAULT_CONN_PASSWORD = "11111111";
    static final String DEFAULT_INI_FILE = "/config.ini";
    static final String DEFAULT_LOG_DIR = "/Szaflog";
    static final String DEFAULT_LOG_FILE = "/szafHsm.log";
    static final int DEFAULT_LOG_LEVEL = 1;
    static final int DEFAULT_CONNECT_TIMEOUT = 30;
    static final int DEFAULT_SERVICE_TIMEOUT = 30;
    static final int DEFAULT_CONNECT_POOLSIZE = 10;
    static final String HSMM = "HSMM";
    static final String CARD = "CARD";
    static final String SOFT = "SOFT";
    static final String DEFAULT_DEV_NAME = "CARD";
    private String configFilePath = null;
    private Logger logger = null;
    private int connect = 0;
    private int service = 0;
    private int poolsize = 0;
    private int deviceType = 0;

    private AFProFile() {
    }
    private static final class ProfileHolder {
        static final AFProFile profile = new AFProFile();
    }
    /**
     * 双重验证获取实例
     */
    public static AFProFile getInstance() {
        return ProfileHolder.profile;
    }

}
