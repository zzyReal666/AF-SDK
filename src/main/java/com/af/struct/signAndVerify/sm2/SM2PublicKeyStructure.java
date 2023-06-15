package com.af.struct.signAndVerify.sm2;

import com.af.crypto.key.sm2.SM2PublicKey;
import com.af.utils.BigIntegerUtil;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Enumeration;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/27 15:55
 */
@Getter
@Setter
@NoArgsConstructor
public class SM2PublicKeyStructure implements ASN1Encodable {


    private BigInteger x;
    private BigInteger y;

    public SM2PublicKeyStructure(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }


    public SM2PublicKeyStructure (SM2PublicKey publicKey) {
        BigInteger x = BigIntegerUtil.toPositiveInteger(publicKey.getX());
        BigInteger y = BigIntegerUtil.toPositiveInteger(publicKey.getY());
        this.x = x;
        this.y = y;
    }

    public SM2PublicKeyStructure(ECPoint Q) {
        this.x = Q.getAffineX();
        this.y = Q.getAffineY();
    }

    public SM2PublicKeyStructure(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.x  = ((ASN1Integer) e.nextElement()).getValue();
        this.y = ((ASN1Integer) e.nextElement()).getValue();
    }

    public SM2PublicKeyStructure(ASN1BitString publicKeyData) {
        byte[] octets = publicKeyData.getBytes();
        byte[] tmp = new byte[32];
        System.arraycopy(octets, 1, tmp, 0, 32);
        this.x = BigIntegerUtil.toPositiveInteger(tmp);
        System.arraycopy(octets, 33, tmp, 0, 32);
        this.y = BigIntegerUtil.toPositiveInteger(tmp);
    }

    public SM2PublicKeyStructure(byte[] octets) {
        byte[] tmp = new byte[32];
        System.arraycopy(octets, 1, tmp, 0, 32);
        this.x = BigIntegerUtil.toPositiveInteger(tmp);
        System.arraycopy(octets, 33, tmp, 0, 32);
        this.y = BigIntegerUtil.toPositiveInteger(tmp);
    }

    public static SM2PublicKeyStructure getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SM2PublicKeyStructure getInstance(Object obj) {
        if (obj instanceof SM2PublicKeyStructure) {
            return (SM2PublicKeyStructure) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new SM2PublicKeyStructure((ASN1Sequence) obj);
        } else {
            throw new IllegalArgumentException("无法解析的Object: " + obj.getClass().getName());
        }
    }

    public byte[] getPublicKey() {
        byte[] publicKey = new byte[65];
        publicKey[0] = 4;
        System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(this.x), 0, publicKey, 1, 32);
        System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(this.y), 0, publicKey, 33, 32);
        return publicKey;
    }


    public SM2PublicKey toSm2PublicKey() {
        byte[] x = BigIntegerUtil.asUnsigned32ByteArray(this.getX());
        byte[] y = BigIntegerUtil.asUnsigned32ByteArray(this.getY());
        return new SM2PublicKey(256, x, y);
    }

    public SM2PublicKeyStructure toSm2PublicKey(SM2PublicKey publicKey) {
        this.x = BigIntegerUtil.toPositiveInteger(publicKey.getX());
        this.y = BigIntegerUtil.toPositiveInteger(publicKey.getY());
        return this;
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(this.x));
        v.add(new ASN1Integer(this.y));

        return new DERSequence(v);
    }
}
