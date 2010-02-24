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
package org.jscep.pkcs9;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * This class represents a PKCS #9 contentType attribute.
 * 
 * @author David Grant
 */
public class ContentTypeAttribute extends Attribute {
	/**
	 * Creates a new instance of <code>ContentTypeAttribute</code> using the provided
	 * contentType.
	 * 
	 * @param contentType the contentType to use.
	 */
	public ContentTypeAttribute(DERObjectIdentifier contentType) {
		super(PKCSObjectIdentifiers.pkcs_9_at_contentType, toSet(contentType));
	}
	
	/**
	 * Creates an ASN1Set suitable for use in an ASN1 Attribute.
	 * 
	 * @param contentType the contentType to use.
	 * @return the set.
	 */
	private static ASN1Set toSet(DERObjectIdentifier contentType) {
		final ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(contentType);
		
		return new DERSet(v);
	}
	
	/**
	 * Returns the content type contained in this contentType attribute.
	 * 
	 * @return the contentType.
	 */
	public DERObjectIdentifier getContentType() {
		return (DERObjectIdentifier) getAttrValues().getObjectAt(0);
		
	}
}
