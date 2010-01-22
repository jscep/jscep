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

package com.google.code.jscep.pkcs7;

import java.security.GeneralSecurityException;

import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.TransactionId;

/**
 * This interface represents the <tt>SCEP</tt> <tt>pkiMessage</tt>.
 *
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-3.1">SCEP Internet-Draft Reference</a>
 */
public interface PkiMessage {
	/**
	 * Returns the failInfo of this response.
	 * 
	 * @return the failInfo.
	 */
	FailInfo getFailInfo();
	/**
	 * Returns the status of this response.
	 * 
	 * @return the status.
	 */
	PkiStatus getPkiStatus();
	/**
	 * Returns the recipient nonce for this response.
	 * 
	 * @return the recipient nonce.
	 */
	Nonce getRecipientNonce();
	/**
	 * Returns the sender nonce for this response.
	 * 
	 * @return the sender nonce.
	 */
	Nonce getSenderNonce();
	/**
	 * Returns the transaction ID for this response.
	 * 
	 * @return the transaction ID.
	 */
	TransactionId getTransactionId();
	/**
	 * Returns the enveloped data.
	 * 
	 * @return the enveloped data.
	 * @throws GeneralSecurityException 
	 * @throws CMSException 
	 */
	PkcsPkiEnvelope getPkcsPkiEnvelope();
	MessageType getMessageType();
	byte[] getEncoded();
}
