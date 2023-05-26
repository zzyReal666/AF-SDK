package com.af.struct.signAndVerify.sm2;


import lombok.Getter;
import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.util.Enumeration;

@Getter
public class SM2CipherStructure implements ASN1Encodable {


    private BigInteger x;
    private BigInteger y;
    private byte[] C;
    private byte[] M;

    public static SM2CipherStructure getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SM2CipherStructure getInstance(Object obj) {
        if (obj instanceof SM2CipherStructure) {
            return (SM2CipherStructure) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new SM2CipherStructure((ASN1Sequence)obj);
        } else {
            throw new IllegalArgumentException("无法解析的Object" + obj.getClass().getName());
        }
    }

    public SM2CipherStructure(BigInteger x, BigInteger y, byte[] C, byte[] M) {
        this.x = x;
        this.y = y;
        this.C = C;
        this.M = M;
    }

    public SM2CipherStructure(ASN1Sequence seq) {
        Enumeration<?> e = seq.getObjects();
        this.x = ((ASN1Integer)e.nextElement()).getValue();
        this.y = ((ASN1Integer)e.nextElement()).getValue();
        this.M = ((DEROctetString)e.nextElement()).getOctets();
        this.C = ((DEROctetString)e.nextElement()).getOctets();
    }



    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(this.getX()));
        v.add(new ASN1Integer(this.getY()));
        v.add(new DEROctetString(this.getM()));
        v.add(new DEROctetString(this.getC()));
        return new DERSequence(v);
    }
}
