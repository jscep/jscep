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
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import com.google.code.jscep.asn1.IssuerAndSubject;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.util.LoggingUtil;

/**
 * This class represents the <tt>SCEP</tt> <tt>GetCertInitial</tt> <tt>pkiMessage</tt> type.
 * 
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-3.2.3">SCEP Internet-Draft Reference</a>
 */
public class GetCertInitial implements PkiOperation {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.operations");
	private final X500Principal issuer;
    private final X500Principal subject;

    public GetCertInitial(X500Principal issuer, X500Principal subject) {
        this.issuer = issuer;
        this.subject = subject;
    }

    /**
     * {@inheritDoc}
     */
    public MessageType getMessageType() {
        return MessageType.GetCertInitial;
    }

    /**
     * Returns a DER-encoded IssuerAndSubject
     * 
     * @return the IssuerAndSubject.
     */
	public byte[] getMessageData() throws IOException {
		return new IssuerAndSubject(issuer, subject).getDEREncoded();
	}
}
