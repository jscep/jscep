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
import java.security.cert.X509Certificate;

import com.google.code.jscep.transaction.MessageType;

/**
 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.2
 */
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
    public MessageType getMessageType() {
        return MessageType.PKCSReq;
    }

    @Override
    public byte[] getMessageData() throws IOException, GeneralSecurityException {
    	Pkcs10CertificationRequest certReq = Pkcs10CertificationRequest.getInstance(keyPair, identity);
    	certReq.addAttribute("1.2.840.113549.1.9.7", new String(password));
    	
    	return certReq.createRequest();
    }

    public String toString() {
    	return getMessageType().toString();
    }
}
