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

package com.google.code.jscep.transaction;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.smime.SMIMECapability;

import com.google.code.jscep.pkcs7.PkcsPkiEnvelopeGenerator;
import com.google.code.jscep.pkcs7.PkiMessageGenerator;
import com.google.code.jscep.transport.Transport;

/**
 * Factory for generating new Transactions.
 * 
 */
public final class TransactionFactory {
	/**
	 * Private constructor to prevent instantiation.
	 */
	private TransactionFactory() {
	}
	
	/**
	 * Create a new SCEP transaction.
	 * 
	 * @param transport the transport to use.
	 * @param ca the CA certificate.
	 * @param identity the certificate to enroll.
	 * @param keyPair the key pair to use.
	 * @param fingerprintAlgorithm the finger print algorithm.
	 * @return thge new transaction.
	 */
	public static Transaction createTransaction(Transport transport, X509Certificate ca, X509Certificate identity, KeyPair keyPair, String fingerprintAlgorithm) {
		// TODO: Don't hardcode DES
		// TODO: BC Dependency
		final PkcsPkiEnvelopeGenerator envGenerator = new PkcsPkiEnvelopeGenerator();
		envGenerator.setCipher(SMIMECapability.dES_CBC.getId());
		envGenerator.setRecipient(ca);

		// TODO: Don't hardcode SHA-1
		// TODO: BC Dependency
		final PkiMessageGenerator msgGenerator = new PkiMessageGenerator();
		msgGenerator.setDigest("1.3.14.3.2.26");
		msgGenerator.setIdentity(identity);
		msgGenerator.setKeyPair(keyPair);
		
		return new Transaction(transport, keyPair, envGenerator, msgGenerator);
	}
}
