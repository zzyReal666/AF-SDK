package com.af.struct.signAndVerify;

import com.af.exception.AFCryptoException;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description csr请求对象
 * @since 2023/8/8 15:55
 */
@Getter
@Setter
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
        //region//======>参数校验
        if (uiDnc == null || uiDnc.isEmpty()) {
            throw new AFCryptoException("国家不能为空");
        }
        if (uiDns == null || uiDns.isEmpty()) {
            throw new AFCryptoException("省不能为空");
        }
        if (uiDnl == null || uiDnl.isEmpty()) {
            throw new AFCryptoException("市不能为空");
        }
        if (uiDno == null || uiDno.isEmpty()) {
            throw new AFCryptoException("组织不能为空");
        }
        if (uiDnou == null || uiDnou.isEmpty()) {
            throw new AFCryptoException("单位不能为空");
        }
        if (uiDnCn == null || uiDnCn.isEmpty()) {
            throw new AFCryptoException("证书使用者信息不能为空");
        }
        if (uiDnEmail == null || uiDnEmail.isEmpty()) {
            throw new AFCryptoException("邮箱不能为空");
        }
        //endregion

        //CN=abc.com,C=CN,OU=abc,S=s,L=s,O=s,Email=s@s.cn
       return "CN="+uiDnCn+",C="+uiDnc+",OU="+uiDnou+",S="+uiDns+",L="+uiDnl+",O="+uiDno+",Email="+uiDnEmail;

    }


}
