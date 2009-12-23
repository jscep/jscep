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

package com.google.code.jscep.asn1;

import java.io.IOException;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * <tt>IssuerAndSubject</tt> <tt>ASN.1</tt> Object
 * <p>
 * The <tt>IssuerAndSubject</tt> object is defined in the <tt>SCEP</tt> Internet-Draft
 * by the following notation:
 * <pre>
 * IssuerAndSubject ::= SEQUENCE {
 *     issuer Name,
 *     subject Name,
 * }
 * </pre>
 * 
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-3.2.3.1">SCEP Internet-Draft Reference</a>
 */
public class IssuerAndSubject {
	private static Logger LOGGER = Logger.getLogger("com.google.code.jscep.asn1");
	private final X500Principal issuer;
	private final X500Principal subject;

	public IssuerAndSubject(X500Principal issuer, X500Principal subject) {
		this.issuer = issuer;
		this.subject = subject;
	}

	public X500Principal getIssuer() {
		return issuer;
	}

	public X500Principal getSubject() {
		return subject;
	}

	public byte[] getDEREncoded() throws IOException {
		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(new X509Name(issuer.getName()));
		v.add(new X509Name(subject.getName()));

		return new DERSequence(v).getDEREncoded();
	}
}
