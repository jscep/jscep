/*
 * Copyright (c) 2009-2010 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
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

import java.io.IOException;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.jscep.transaction.MessageType;


/**
 * This class represents the SCEP <code>PKCSReq</code> <code>pkiMessage</code>
 * type.
 * 
 * @author David Grant
 */
public class PkcsReq implements PkiOperation<CertificationRequest> {
    private final CertificationRequest csr;

    public PkcsReq(CertificationRequest csr) {
        this.csr = csr;
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
    	return csr;
    }
    
    /**
	 * {@inheritDoc}
	 */
    @Override
    public String toString() {
    	return getMessageType().toString();
    }
}
