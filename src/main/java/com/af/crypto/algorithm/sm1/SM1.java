package com.af.crypto.algorithm.sm1;

import com.af.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/27 15:05
 */
public interface SM1 {



    byte[] SM1EncryptECB(int index, byte[] data) throws AFCryptoException;
    byte[] SM1EncryptECB(byte[] key, byte[] data)throws AFCryptoException;

    byte[] SM1DecryptECB(int index, byte[] encodeData)throws AFCryptoException;
    byte[] SM1DecryptECB(byte[] key, byte[] encodeData)throws AFCryptoException;

    byte[] SM1EncryptCBC(int index, byte[] iv, byte[] data)throws AFCryptoException;
    byte[] SM1EncryptCBC(byte[] key, byte[] iv, byte[] data)throws AFCryptoException;

    byte[] SM1DecryptCBC(int index, byte[] iv, byte[] encodeData)throws AFCryptoException;
    byte[] SM1DecryptCBC(byte[] key, byte[] iv, byte[] encodeData)throws AFCryptoException;



}
