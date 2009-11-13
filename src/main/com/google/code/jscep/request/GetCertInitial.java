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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;

import com.google.code.jscep.asn1.IssuerAndSubject;
import com.google.code.jscep.transaction.MessageType;

/**
 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.3
 */
public class GetCertInitial implements PkiOperation {
	private final X500Principal issuer;
    private final X500Principal subject;

    public GetCertInitial(X500Principal issuer, X500Principal subject) {
        this.issuer = issuer;
        this.subject = subject;
    }

    @Override
    public MessageType getMessageType() {
        return MessageType.GetCertInitial;
    }

    @Override
	public byte[] getMessageData() throws IOException {
    	// TODO: BC Dependency
        X509Name issuerName = new X509Principal(issuer.getEncoded());
        X509Name subjectName = new X509Principal(subject.getEncoded());

        return new IssuerAndSubject(issuerName, subjectName).getEncoded();
    }
    
    public String toString() {
    	return getMessageType().toString();
    }
}
