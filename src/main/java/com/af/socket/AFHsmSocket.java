package com.af.socket;

import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description socket
 * @since 2023/4/18 16:07
 */
@Getter
@Setter

public class AFHsmSocket {

    private static final Logger logger = LoggerFactory.getLogger(AFHsmSocket.class);

    private String ip;
    private String passwd;
    private int port;
    private int connectTimeout;
    private int serviceTimeout;
    private Socket socket;
    private int status;
    private OutputStream out;
    private InputStream in;

    public AFHsmSocket(String ip, String passwd, int port, int connectTimeout, int serviceTimeout) {
        this.ip = ip;
        this.passwd = passwd;
        this.port = port;
        this.connectTimeout = connectTimeout;
        this.serviceTimeout = serviceTimeout;
        this.status = 1;
    }

}
