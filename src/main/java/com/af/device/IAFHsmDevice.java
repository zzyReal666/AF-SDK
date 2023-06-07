package com.af.device;

import com.af.constant.GroupMode;
import com.af.constant.ModulusLength;
import com.af.crypto.key.sm2.SM2KeyPair;
import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.struct.impl.RSA.RSAKeyPair;
import com.af.struct.impl.RSA.RSAPriKey;
import com.af.struct.impl.RSA.RSAPubKey;
import com.af.struct.impl.sm2.SM2Cipher;
import com.af.struct.impl.sm2.SM2Signature;
import com.af.exception.AFCryptoException;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description HSM设备接口
 * @since 2023/5/16 9:16
 */
public interface IAFHsmDevice extends IAFDevice {

}
