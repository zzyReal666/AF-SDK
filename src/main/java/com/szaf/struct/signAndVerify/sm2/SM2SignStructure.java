package com.szaf.struct.signAndVerify.sm2;

import com.szaf.struct.impl.sm2.SM2Signature;
import com.szaf.utils.BigIntegerUtil;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.util.Enumeration;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description SM2签名结构  todo 目前使用bc库ASN结构序列化,是否需要自己实现?
 * @since 2023/5/24 15:35
 */
@Getter
@AllArgsConstructor
public class SM2SignStructure implements ASN1Encodable {
    private BigInteger r;
    private BigInteger s;
    //构造
    public SM2SignStructure(ASN1Sequence seq) {
        Enumeration<?> e = seq.getObjects();
        this.r = ((ASN1Integer) e.nextElement()).getValue();
        this.s = ((ASN1Integer) e.nextElement()).getValue();
    }
    public SM2SignStructure(SM2Signature signature) {
        this.r = BigIntegerUtil.toPositiveInteger(signature.getR());
        this.s = BigIntegerUtil.toPositiveInteger(signature.getS());
    }

    /**
     * 将ASN1TaggedObject转换为SM2SignStructure
     * @param obj ASN1TaggedObject
     * @param explicit boolean
     * @return SM2SignStructure SM2签名结构
     */
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

    /**
     * 将SM2SignStructure转换为ASN1Primitive
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(this.getR()));
        v.add(new ASN1Integer(this.getS()));
        return new DERSequence(v);
    }
}
