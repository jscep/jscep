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
package org.jscep.operations;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.jscep.pkcs9.ChallengePasswordAttribute;
import org.jscep.transaction.MessageType;
import org.jscep.util.AlgorithmDictionary;


/**
 * This class represents the SCEP <code>PKCSReq</code> <code>pkiMessage</code>
 * type.
 * 
 * @author David Grant
 */
public class PKCSReq implements DelayablePKIOperation<CertificationRequest> {
    private final X509Certificate identity;
    private final char[] password;
    private final KeyPair keyPair;
    private final String digestAlgorithm;

    public PKCSReq(KeyPair keyPair, X509Certificate identity, String digestAlgorithm, char[] password) {
        this.keyPair = keyPair;
        this.identity = identity;
        this.password = password;
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * {@inheritDoc}
     */
    public MessageType getMessageType() {
        return MessageType.PKCSReq;
    }

    /**
     * Returns a Certification Request.
     * 
     * @return the Certification Request
     * @see <a href="http://tools.ietf.org/html/rfc2986">RFC 2986</a>
     */
    public CertificationRequest getMessage() throws IOException {
		try {
			final CertificationRequestInfo info = getCertificationRequestInfo();
			return new CertificationRequest(info, getSignatureAlgorithm(), sign(info));
			
		} catch (GeneralSecurityException e) {
			throw new IOException(e);
		}
    }
    
    private CertificationRequestInfo getCertificationRequestInfo() throws IOException {
		return new CertificationRequestInfo(getSubject(), getPublicKeyInfo(), getAttributes());
    }

	private X509Name getSubject() {
		return new X509Name(identity.getSubjectX500Principal().getName());
	}

	private DERSet getAttributes() {
		final ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new ChallengePasswordAttribute(new String(password)));
		
		return new DERSet(v);
	}
    
    private DERBitString sign(CertificationRequestInfo info) throws GeneralSecurityException {
    	Signature signature = Signature.getInstance(AlgorithmDictionary.lookup(getSignatureAlgorithm()));
    	signature.initSign(keyPair.getPrivate());
    	signature.update(info.getDEREncoded());
    	
    	return new DERBitString(signature.sign());
    }
    
    private SubjectPublicKeyInfo getPublicKeyInfo() throws IOException {
    	final ByteArrayInputStream bIn = new ByteArrayInputStream(keyPair.getPublic().getEncoded());
		final ASN1InputStream dIn = new ASN1InputStream(bIn);
		
    	return new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
    }
    
    private AlgorithmIdentifier getSignatureAlgorithm() {
    	return new AlgorithmIdentifier(AlgorithmDictionary.getOid(AlgorithmDictionary.getRSASignatureAlgorithm(digestAlgorithm)));
    }
    
    /**
	 * {@inheritDoc}
	 */
    @Override
    public String toString() {
    	return getMessageType().toString();
    }
}
