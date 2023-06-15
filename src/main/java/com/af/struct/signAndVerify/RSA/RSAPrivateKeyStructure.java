package com.af.struct.signAndVerify.RSA;

import com.af.struct.impl.RSA.RSAPriKey;
import com.af.utils.BigIntegerUtil;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.util.Enumeration;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/6/5 15:54
 */
@Getter
@Setter
@NoArgsConstructor
public class RSAPrivateKeyStructure implements ASN1Encodable {

    private int version;
    private BigInteger modulus;
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger prime1;
    private BigInteger prime2;
    private BigInteger exponent1;
    private BigInteger exponent2;
    private BigInteger coefficient;
    private ASN1Sequence otherPrimeInfos = null;

    public static RSAPrivateKeyStructure getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RSAPrivateKeyStructure getInstance(
            Object obj) {
        if (obj instanceof RSAPrivateKeyStructure) {
            return (RSAPrivateKeyStructure) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new RSAPrivateKeyStructure((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public RSAPrivateKeyStructure(
            BigInteger modulus,
            BigInteger publicExponent,
            BigInteger privateExponent,
            BigInteger prime1,
            BigInteger prime2,
            BigInteger exponent1,
            BigInteger exponent2,
            BigInteger coefficient) {
        this.version = 0;
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.prime1 = prime1;
        this.prime2 = prime2;
        this.exponent1 = exponent1;
        this.exponent2 = exponent2;
        this.coefficient = coefficient;
    }

    public RSAPrivateKeyStructure(RSAPriKey prvKey) {
        this.modulus = BigIntegerUtil.toPositiveInteger(prvKey.getM());
        this.publicExponent = BigIntegerUtil.toPositiveInteger(prvKey.getE());
        this.privateExponent = BigIntegerUtil.toPositiveInteger(prvKey.getD());
        this.prime1 = BigIntegerUtil.toPositiveInteger(prvKey.getP());
        this.prime2 = BigIntegerUtil.toPositiveInteger(prvKey.getQ());
        this.exponent1 = BigIntegerUtil.toPositiveInteger(prvKey.getDp());
        this.exponent2 = BigIntegerUtil.toPositiveInteger(prvKey.getDq());
        this.coefficient = BigIntegerUtil.toPositiveInteger(prvKey.getCof());
    }

    public RSAPriKey toRSAPriKey() {
        RSAPriKey prvKey = new RSAPriKey();
        int length = modulus.bitLength();
        byte[] m = BigIntegerUtil.toByteArray(modulus);
        byte[] e = BigIntegerUtil.toByteArray(publicExponent);
        byte[] d = BigIntegerUtil.toByteArray(privateExponent);
        byte[] p = BigIntegerUtil.toByteArray(prime1);
        byte[] q = BigIntegerUtil.toByteArray(prime2);
        byte[] dp = BigIntegerUtil.toByteArray(exponent1);
        byte[] dq = BigIntegerUtil.toByteArray(exponent2);
        byte[] cof = BigIntegerUtil.toByteArray(coefficient);


        //前面补0 m,e 补满2048位,其他补满1024位
        byte[] m1 = new byte[256];
        byte[] e1 = new byte[256];
        byte[] d1 = new byte[256];
        byte[] p1 = new byte[128];
        byte[] q1 = new byte[128];
        byte[] dp1 = new byte[128];
        byte[] dq1 = new byte[128];
        byte[] cof1 = new byte[128];

        System.arraycopy(m, 0, m1, 256 - m.length, m.length);
        System.arraycopy(e, 0, e1, 256 - e.length, e.length);
        System.arraycopy(d, 0, d1, 256 - d.length, d.length);
        System.arraycopy(p, 0, p1, 128 - p.length, p.length);
        System.arraycopy(q, 0, q1, 128 - q.length, q.length);
        System.arraycopy(dp, 0, dp1, 128 - dp.length, dp.length);
        System.arraycopy(dq, 0, dq1, 128 - dq.length, dq.length);
        System.arraycopy(cof, 0, cof1, 128 - cof.length, cof.length);


        prvKey.setBits(length);
        prvKey.setM(m1);
        prvKey.setE(e1);
        prvKey.setD(d1);
        prvKey.setP(p1);
        prvKey.setQ(q1);
        prvKey.setDp(dp1);
        prvKey.setDq(dq1);
        prvKey.setCof(cof1);

        return prvKey;
    }

    public RSAPrivateKeyStructure(
            ASN1Sequence seq) {
        Enumeration e = seq.getObjects();

        BigInteger v = ((ASN1Integer) e.nextElement()).getValue();
        if (v.intValue() != 0 && v.intValue() != 1) {
            throw new IllegalArgumentException("wrong version for RSA private key");
        }

        version = v.intValue();
        modulus = ((ASN1Integer) e.nextElement()).getValue();
        publicExponent = ((ASN1Integer) e.nextElement()).getValue();
        privateExponent = ((ASN1Integer) e.nextElement()).getValue();
        prime1 = ((ASN1Integer) e.nextElement()).getValue();
        prime2 = ((ASN1Integer) e.nextElement()).getValue();
        exponent1 = ((ASN1Integer) e.nextElement()).getValue();
        exponent2 = ((ASN1Integer) e.nextElement()).getValue();
        coefficient = ((ASN1Integer) e.nextElement()).getValue();

        if (e.hasMoreElements()) {
            otherPrimeInfos = (ASN1Sequence) e.nextElement();
        }
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(version));                       // version
        v.add(new ASN1Integer(getModulus()));
        v.add(new ASN1Integer(getPublicExponent()));
        v.add(new ASN1Integer(getPrivateExponent()));
        v.add(new ASN1Integer(getPrime1()));
        v.add(new ASN1Integer(getPrime2()));
        v.add(new ASN1Integer(getExponent1()));
        v.add(new ASN1Integer(getExponent2()));
        v.add(new ASN1Integer(getCoefficient()));

        if (otherPrimeInfos != null) {
            v.add(otherPrimeInfos);
        }
        return new DERSequence(v);
    }
}
