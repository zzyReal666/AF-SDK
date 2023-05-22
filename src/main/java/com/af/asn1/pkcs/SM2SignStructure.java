package com.af.asn1.pkcs;


import com.af.asn1.ASN1Encodable;
import com.af.asn1.DERObject;
import com.af.securityAccess.asn1.DERInteger;
import com.af.securityAccess.crypto.SM2SignatureByM256;

import java.math.BigInteger;
import java.util.Enumeration;

public class SM2SignStructure extends ASN1Encodable {
    private BigInteger r;
    private BigInteger s;

    public SM2SignStructure(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }
    public SM2SignStructure(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.r = ((DERInteger) e.nextElement()).getValue();
        this.s = ((DERInteger) e.nextElement()).getValue();
    }

    public SM2SignStructure(SM2SignatureByM256 signature) {
        this.r = BigIntegerUtil.toPositiveInteger(signature.getR());
        this.s = BigIntegerUtil.toPositiveInteger(signature.getS());
    }

    public static SM2SignStructure getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SM2SignStructure getInstance(Object obj) {
        if (obj instanceof SM2SignStructure) {
            return (SM2SignStructure) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new SM2SignStructure((ASN1Sequence) obj);
        } else {
            throw new IllegalArgumentException("无法解析的Object" + obj.getClass().getName());
        }
    }

    public BigInteger getR() {
        return r;
    }

    public BigInteger getS() {
        return s;
    }

    @Override
    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(this.getR()));
        v.add(new DERInteger(this.getS()));

        return new DERSequence(v);
    }
}
