package com.af.struct.signAndVerify;

import com.af.exception.AFCryptoException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description csr请求对象
 * @since 2023/8/8 15:55
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CsrRequest {

    /**
     * 国家
     */
    private String uiDnc;

    /**
     * 省
     */
    private String uiDns;

    /**
     * 市
     */
    private String uiDnl;

    /**
     * 组织
     */
    private String uiDno;

    /**
     * 单位
     */
    private String uiDnou;

    /**
     * 证书使用者信息
     */
    private String uiDnCn;

    /**
     * 邮箱
     */
    private String uiDnEmail;


    public String toDn() throws AFCryptoException {
        if (uiDnCn == null || uiDnCn.isEmpty()) {
            throw new AFCryptoException("证书使用者信息不能为空");
        }
        StringBuilder dn = new StringBuilder();
        if (uiDnc != null && !uiDnc.isEmpty()) {
            dn.append("C=").append(uiDnc).append(",");
        }
        if (uiDns != null && !uiDns.isEmpty()) {
            dn.append("S=").append(uiDns).append(",");
        }
        if (uiDnl != null && !uiDnl.isEmpty()) {
            dn.append("L=").append(uiDnl).append(",");
        }
        if (uiDno != null && !uiDno.isEmpty()) {
            dn.append("O=").append(uiDno).append(",");
        }
        if (uiDnou != null && !uiDnou.isEmpty()) {
            dn.append("OU=").append(uiDnou).append(",");
        }
        dn.append("CN=").append(uiDnCn).append(",");
        if (uiDnEmail != null && !uiDnEmail.isEmpty()) {
            dn.append("EMAILADDRESS=").append(uiDnEmail).append(",");
        }
        if (dn.length() > 0) {
            dn.deleteCharAt(dn.length() - 1);
        }
        return dn.toString();

    }


}
