package com.szaf.netty;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/16 11:16
 */
public class AFNettyClientBuilder {
    //建造者
    private AFNettyClient afNettyClient;





    public AFNettyClientBuilder host(int maxRetry) {
        afNettyClient.setMAX_RETRY(maxRetry);
        return this;
    }

    public AFNettyClientBuilder port(int retryDelay) {
        afNettyClient.setRETRY_DELAY(retryDelay);
        return this;
    }

}
