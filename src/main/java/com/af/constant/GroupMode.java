package com.af.constant;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description 分组模式 当前支持ECB和CBC
 * @since 2023/4/27 15:24
 */
public enum GroupMode {
    ECB("ECB"),      //Electronic Codebook 电子密码本
    CBC("CBC");      //Cipher Block Chaining 密码块链接
    // CFB("CFB"),   //Cipher Feedback 密码反馈
    // OFB("OFB"),  //Output Feedback  输出反馈
    // CTR("CTR");  //Counter 计数器

    private final String mode;

    GroupMode(String mode) {
        this.mode = mode;
    }

    public String getMode() {
        return mode;
    }
}
