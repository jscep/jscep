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

package com.google.code.jscep.operations;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import com.google.code.jscep.pkcs9.ChallengePassword;
import com.google.code.jscep.transaction.MessageType;

/**
 * This class represents the <tt>SCEP</tt> <tt>PKCSReq</tt> <tt>pkiMessage</tt> type.
 * 
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-3.2.1">SCEP Internet-Draft Reference</a>
 */
public class PkcsReq implements PkiOperation<PKCS10CertificationRequest> {
    private final X509Certificate identity;
    private final char[] password;
    private final KeyPair keyPair;

    public PkcsReq(KeyPair keyPair, X509Certificate identity, String digestAlgorithm, char[] password) {
        this.keyPair = keyPair;
        this.identity = identity;
        this.password = password;
    }

    /**
     * {@inheritDoc}
     */
    public MessageType getMessageType() {
        return MessageType.PKCSReq;
    }

    /**
     * Returns a DER-encoded PKCS#10 Certificate Request.
     * 
     * @return the Certification Request
     * @see <a href="http://tools.ietf.org/html/rfc2986">RFC 2986</a>
     */
    public PKCS10CertificationRequest getMessageData() throws IOException {
    	X500Principal subject = identity.getSubjectX500Principal();
    	PublicKey pub = keyPair.getPublic();
		PrivateKey priv = keyPair.getPrivate();
        
		final ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new ChallengePassword(new String(password)));
		DERSet set = new DERSet(v);
		
		try {
			return new PKCS10CertificationRequest("SHA1withRSA", subject, pub, set, priv, "SunRsaSign");
		} catch (GeneralSecurityException e) {
			throw new IOException(e);
		}
    }
}
