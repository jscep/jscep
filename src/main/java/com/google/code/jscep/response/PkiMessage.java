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

package com.google.code.jscep.response;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;

import com.google.code.jscep.transaction.CmsException;
import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.TransactionId;

/**
 * This class represents the <tt>SCEP</tt> <tt>pkiMessage</tt>.
 *
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-3.1">SCEP Internet-Draft Reference</a>
 */
public abstract class PkiMessage {
	public abstract FailInfo getFailInfo();
	public abstract PkiStatus getStatus();
	/**
	 * Returns the recipient nonce for this response.
	 * 
	 * @return the recipient nonce.
	 */
	public abstract Nonce getRecipientNonce();
	/**
	 * Returns the sender nonce for this response.
	 * 
	 * @return the sender nonce.
	 */
	public abstract Nonce getSenderNonce();
	/**
	 * Returns the transaction ID for this response.
	 * 
	 * @return the transaction ID.
	 */
	public abstract TransactionId getTransactionId();
	/**
	 * Returns the certificate store for this response.
	 * 
	 * @return the certificate store.
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws CmsException
	 */
	public abstract CertStore getCertStore() throws NoSuchProviderException, NoSuchAlgorithmException, CmsException;
	
	/**
	 * 
	 * @param keyPair
	 * @param bytes DER-encoded degenerate certificates-only signedData
	 * @return
	 * @throws CmsException
	 */
	public static PkiMessage getInstance(KeyPair keyPair, byte[] bytes) throws CmsException {
		return new PkiMessageImpl(keyPair, bytes);
	}
}
