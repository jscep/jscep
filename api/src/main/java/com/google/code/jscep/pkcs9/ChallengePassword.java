package com.google.code.jscep.pkcs9;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public class ChallengePassword extends Attribute {
	public ChallengePassword(ASN1Sequence seq) {
		super(seq);
	}
	
	public ChallengePassword(String password) {
		super(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, asSet(password));
	}
	
	private static ASN1Set asSet(String password) {
		final ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new DERPrintableString(password));
		
		return new DERSet(v);
	}
}
