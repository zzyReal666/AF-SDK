package com.szaf.struct;

import com.szaf.exception.AFCryptoException;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 11:02
 */
public interface IAFStruct {
    int LiteRSARef_MAX_BITS = 2048;
    int LiteRSARef_MAX_LEN = ((LiteRSARef_MAX_BITS + 7) / 8);
    int LiteRSARef_MAX_PBITS = ((LiteRSARef_MAX_BITS + 1) / 2);
    int LiteRSARef_MAX_PLEN = ((LiteRSARef_MAX_PBITS + 7) / 8);

    int ExRSARef_MAX_BITS = 4096;
    int ExRSARef_MAX_LEN = ((ExRSARef_MAX_BITS + 7) / 8);
    int ExRSARef_MAX_PBITS = ((ExRSARef_MAX_BITS + 1) / 2);
    int ExRSARef_MAX_PLEN = ((ExRSARef_MAX_PBITS + 7) / 8);

    int EXP_ECCref_MAX_BITS = 256;
    int EXP_ECCref_MAX_LEN = ((EXP_ECCref_MAX_BITS + 7) / 8);
    int EXP_ECCref_MAX_CIPHER_LEN = 136;

    int ECCref_MAX_BITS = 512;
    int ECCref_MAX_LEN = ((ECCref_MAX_BITS + 7) / 8);
    int ECCref_MAX_CIPHER_LEN = 136;

    int size();

    void decode(byte[] data) throws AFCryptoException;

    byte[] encode();
}
