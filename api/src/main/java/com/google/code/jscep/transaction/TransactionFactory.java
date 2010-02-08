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
package com.google.code.jscep.transaction;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import com.google.code.jscep.pkcs7.PkiMessageGenerator;
import com.google.code.jscep.transport.Transport;
import com.google.code.jscep.util.LoggingUtil;

/**
 * Factory for generating new Transactions.
 * 
 * @author David Grant
 */
public final class TransactionFactory {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.transaction");
	/**
	 * Private constructor to prevent instantiation.
	 */
	private TransactionFactory() {
	}
	
	/**
	 * Create a new SCEP transaction.
	 * 
	 * @param transport the transport to use.
	 * @param issuer the CA certificate.
	 * @param subject the certificate to enroll.
	 * @param keyPair the key pair to use.
	 * @param digestAlgorithm the finger print algorithm.
	 * @return the new transaction.
	 */
	public static Transaction createTransaction(Transport transport, X509Certificate issuer, X509Certificate subject, KeyPair keyPair, String digestAlgorithm) {
		LOGGER.entering(TransactionFactory.class.getName(), "createTransaction");

		final PkiMessageGenerator msgGenerator = new PkiMessageGenerator();
		msgGenerator.setMessageDigest(digestAlgorithm);
		msgGenerator.setSigner(subject);
		msgGenerator.setKeyPair(keyPair);
		msgGenerator.setCipherAlgorithm("DES");
		msgGenerator.setRecipient(issuer);
		
		Transaction t = new Transaction(transport, keyPair, msgGenerator, digestAlgorithm, issuer, subject);
		
		LOGGER.exiting (TransactionFactory.class.getName(), "createTransaction", t);
		return t;
	}
}
