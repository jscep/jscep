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

package com.google.code.jscep.request;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import com.google.code.jscep.asn1.MessageType;

public class PkcsReq implements PkiOperation {
    private final X509Certificate identity;
    private final char[] password;
    private final KeyPair keyPair;

    public PkcsReq(KeyPair keyPair, X509Certificate identity, char[] password) {
        this.keyPair = keyPair;
        this.identity = identity;
        this.password = password;
    }

    @Override
    public DERPrintableString getMessageType() {
        return MessageType.PKCSReq;
    }

    @Override
    public DEREncodable getMessageData() throws IOException, GeneralSecurityException {
    	PrivateKey priv = keyPair.getPrivate();
    	PublicKey pub = keyPair.getPublic();
    	X500Principal subject = identity.getSubjectX500Principal();
    	
    	return new PKCS10CertificationRequest("SHA1withRSA", subject, pub, getAttributes(), priv);
    }

	private DERSet getAttributes() {
		ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(getPassword());
        
        return new DERSet(attributes);
	}

    private DERSequence getPassword() {
        ASN1Encodable attrType = PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
        ASN1EncodableVector attrValues = new ASN1EncodableVector();
        attrValues.add(new DERUTF8String(new String(password)));
        ASN1EncodableVector attrVector = new ASN1EncodableVector();
        attrVector.add(attrType);
        attrVector.add(new DERSet(attrValues));

        return new DERSequence(attrVector);
    }
    
    public String toString() {
    	return getMessageType().getString();
    }
}
