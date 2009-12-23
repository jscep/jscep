/*
 * Copyright (c) 2009 David Grant
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

package com.google.code.jscep.pkcs10;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import com.google.code.jscep.util.HexUtil;
import com.google.code.jscep.util.LoggingUtil;

/**
 * Implementation of {@link Pkcs10CertificationRequest} that uses Bouncy Castle.
 */
public class Pkcs10CertificationRequestImpl extends Pkcs10CertificationRequest {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs10");
	private final KeyPair keyPair;
	private final X509Certificate identity;
	private final Set<DEREncodable> attrs = new HashSet<DEREncodable>();
	
	Pkcs10CertificationRequestImpl(KeyPair keyPair, X509Certificate identity) {
		this.keyPair = keyPair;
		this.identity = identity;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttribute(String oid, Object attr) {
		DERObjectIdentifier objectId = new DERObjectIdentifier(oid);
		ASN1EncodableVector attrValues = new ASN1EncodableVector();
		attrValues.add(new DERUTF8String(attr.toString()));
		ASN1EncodableVector attrVector = new ASN1EncodableVector();
        attrVector.add(objectId);
        attrVector.add(new DERSet(attrValues));
        
        attrs.add(new DERSequence(attrVector));
	}
	
	private DERSet getAttributes() throws IOException {
		ASN1EncodableVector attributes = new ASN1EncodableVector();
		for (DEREncodable attr : attrs) {
			attributes.add(attr);
		}
        
        return new DERSet(attributes);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] getEncoded() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException {
		X500Principal subject = identity.getSubjectX500Principal();
		LOGGER.info("Generating PKCS #10 Request for " + subject);
		PublicKey pub = keyPair.getPublic();
		PrivateKey priv = keyPair.getPrivate();
		
		CertificationRequest request = new PKCS10CertificationRequest("SHA1withRSA", subject, pub, getAttributes(), priv, "SunRsaSign");
		byte[] requestBytes = request.getDEREncoded();
		
		LOGGER.info("Generated PKCS #10 Request:\n" + HexUtil.formatHex(HexUtil.toHex(requestBytes)));
		
		return requestBytes;
	}
}
