package com.af.struct.signAndVerify.sm2;

import com.af.crypto.key.sm2.SM2PrivateKey;
import com.af.utils.BigIntegerUtil;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.util.Enumeration;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/5/24 16:59
 */
public class SM2PrivateKeyStructure implements ASN1Encodable {

    private ASN1Sequence seq;
    private boolean isCA;


    public SM2PrivateKeyStructure(ASN1Sequence seq) {
        //todo isCA一直为false,是否需要修改?
        this.isCA = false;
        this.seq = seq;
    }

    public SM2PrivateKeyStructure(BigInteger key) {
        this.isCA = false;
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(1));
        if (this.isCA) {
            byte[] bytes = BigIntegers.asUnsignedByteArray(key);
            v.add(new DEROctetString(bytes));
        } else {
            v.add(new ASN1Integer(key));
        }

        this.seq = new DERSequence(v);
    }

    public SM2PrivateKeyStructure(BigInteger key, ASN1Encodable parameters) {
        this(key, (DERBitString) null, parameters);
    }

    public SM2PrivateKeyStructure(BigInteger key, DERBitString publicKey, ASN1Encodable parameters) {
        this.isCA = false;
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(1));
        if (this.isCA) {
            byte[] bytes = BigIntegers.asUnsignedByteArray(key);
            v.add(new DEROctetString(bytes));
        } else {
            v.add(new ASN1Integer(key));
        }
        if (parameters != null) {
            v.add(new DERTaggedObject(true, 0, parameters));
        }
        if (publicKey != null) {
            v.add(new DERTaggedObject(true, 1, publicKey));
        }
        this.seq = new DERSequence(v);
    }


    public BigInteger getKey() {
        if (this.isCA) {
            ASN1OctetString octs = (ASN1OctetString)this.seq.getObjectAt(1);
            return new BigInteger(1, octs.getOctets());
        } else {
            ASN1Integer key = (ASN1Integer)this.seq.getObjectAt(1);
            return key.getValue();
        }
    }


    public DERBitString getPublicKey() {
        return (DERBitString)this.getObjectInTag(1);
    }

    public ASN1Object getParameters() {
        return this.getObjectInTag(0);
    }

    private ASN1Object getObjectInTag(int tagNo) {
        Enumeration<?> e = this.seq.getObjects();
        while(e.hasMoreElements()) {
            ASN1Encodable obj = (ASN1Encodable)e.nextElement();
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject tag = (ASN1TaggedObject)obj;
                if (tag.getTagNo() == tagNo) {
                    return tag.getObject();
                }
            }
        }
        return null;
    }



    public SM2PrivateKey toSM2PrivateKey() {
        return new SM2PrivateKey( BigIntegerUtil.asUnsigned32ByteArray(this.getKey()));
    }







    @Override
    public ASN1Primitive toASN1Primitive() {
        return seq;
    }
}
