package com.af.struct.signAndVerify.RSA;

import com.af.struct.impl.RSA.RSAPubKey;
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
@Setter
@Getter
@NoArgsConstructor
public class RSAPublicKeyStructure implements ASN1Encodable {

    private BigInteger modulus;
    private BigInteger publicExponent;

    public RSAPublicKeyStructure(BigInteger modulus, BigInteger publicExponent) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
    }

    public RSAPublicKeyStructure(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.modulus = ((ASN1Integer) e.nextElement()).getValue();
        this.publicExponent = ((ASN1Integer) e.nextElement()).getValue();
    }

    public RSAPublicKeyStructure(RSAPubKey pubKey) {
        this.modulus = BigIntegerUtil.toPositiveInteger(pubKey.getM());
        this.publicExponent = BigIntegerUtil.toPositiveInteger(pubKey.getE());
    }

    public static RSAPublicKeyStructure getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RSAPublicKeyStructure getInstance(Object obj) {
        if (obj instanceof RSAPublicKeyStructure) {
            return (RSAPublicKeyStructure) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new RSAPublicKeyStructure((ASN1Sequence) obj);
        } else {
            throw new IllegalArgumentException("无法解析的Object" + obj.getClass().getName());
        }
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(this.getModulus()));
        v.add(new ASN1Integer(this.getPublicExponent()));

        return new DERSequence(v);
    }
}
