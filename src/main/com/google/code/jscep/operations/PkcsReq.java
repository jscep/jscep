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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import com.google.code.jscep.request.Pkcs10CertificationRequest;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.util.HexUtil;

/**
 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.2
 */
public class PkcsReq implements PkiOperation {
	private final static Logger LOGGER = Logger.getLogger(PkcsReq.class.getName());
    private final X509Certificate identity;
    private final char[] password;
    private final KeyPair keyPair;
    private final String digestAlgorithm;

    public PkcsReq(KeyPair keyPair, X509Certificate identity, String digestAlgorithm, char[] password) {
        this.keyPair = keyPair;
        this.identity = identity;
        this.digestAlgorithm = digestAlgorithm;
        this.password = password;
    }

    /**
     * {@inheritDoc}
     */
    public MessageType getMessageType() {
        return MessageType.PKCSReq;
    }

    /**
     * {@inheritDoc}
     */
    public byte[] getMessageData() throws IOException, GeneralSecurityException {
    	Pkcs10CertificationRequest certReq = Pkcs10CertificationRequest.getInstance(keyPair, identity);
    	certReq.addAttribute("1.2.840.113549.1.9.7", new String(password));
    	
    	byte[] pkcs10 = certReq.createRequest();
    	byte[] digest = calculateDigest(pkcs10);
    	
    	LOGGER.info("PKCS #10 Digest (" + digestAlgorithm + "):\n" + HexUtil.formatHex(HexUtil.toHex(digest)));
    	
    	return pkcs10;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
    	return getMessageType().toString();
    }
    
    private byte[] calculateDigest(byte[] pkcs10) throws NoSuchAlgorithmException {
    	MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
    	
    	return digest.digest(pkcs10);
    }
}
