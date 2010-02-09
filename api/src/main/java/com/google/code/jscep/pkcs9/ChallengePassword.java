/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.google.code.jscep.pkcs9;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * This class represents a PKCS #9 challengePassword attribute.
 * 
 * @author David Grant
 */
public class ChallengePassword extends Attribute {
	/**
	 * Creates a new instance of <code>ChallengePassword</code> using the provided
	 * password.
	 * 
	 * @param password the password to use.
	 */
	public ChallengePassword(String password) {
		super(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, toSet(password));
	}
	
	/**
	 * Creates an ASN1Set suitable for use in an ASN1 Attribute.
	 * 
	 * @param password the password to use.
	 * @return the set.
	 */
	private static ASN1Set toSet(String password) {
		final ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new DERPrintableString(password));
		
		return new DERSet(v);
	}
	
	/**
	 * Returns the password contained in this challengePassword attribute.
	 * 
	 * @return the password.
	 */
	public String getPassword() {
		final DERPrintableString passwordString = (DERPrintableString) getAttrValues().getObjectAt(0);
		
		return passwordString.getString();
		
	}
}
