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

package com.google.code.jscep;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;
import java.util.logging.Logger;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509CertStoreSelector;

import com.google.code.jscep.operations.PkcsReq;
import com.google.code.jscep.operations.PkiOperation;
import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.transaction.TransactionFactory;
import com.google.code.jscep.transport.Transport;
import com.google.code.jscep.util.LoggingUtil;

/**
 * This class represents the initial attempt at enrolling a certificate in a PKI.
 */
public final class InitialEnrollmentTask extends AbstractEnrollmentTask {
	private static Logger LOGGER = LoggingUtil.getLogger(Client.class);
	private final Transport transport;
	private final X509Certificate ca;
	private final KeyPair keyPair;
	private final X509Certificate identity;
	private final char[] password;
	private final String digestAlgorithm;

	/**
	 * Creates a new instance of this class.
	 * 
	 * @param transport the transport to send enrolment requests over.
	 * @param ca the CA to sign our request.
	 * @param keyPair the key pair used for creating a CSR.
	 * @param identity the identity of the certificate to enrol.
	 * @param password the password to authorise our request.
	 * @param digestAlgorithm the message digest algorithm to use.
	 */
	InitialEnrollmentTask(Transport transport, X509Certificate ca, KeyPair keyPair, X509Certificate identity, char[] password, String digestAlgorithm) {
		this.transport = transport;
		this.ca = ca;
		this.keyPair = keyPair;
		this.identity = identity;
		this.password = password;
		this.digestAlgorithm = digestAlgorithm;
	}
	
	/**
	 * Attempts an enrolment.
	 * @throws IOException 
	 */
	@Override
	public EnrollmentResult call() throws IOException {
		Transaction trans = TransactionFactory.createTransaction(transport, ca, identity, keyPair, digestAlgorithm);
		PkiOperation<PKCS10CertificationRequest> req = new PkcsReq(keyPair, identity, digestAlgorithm, password);
		try {
			CertStore store = trans.performOperation(req);
			
			return new EnrollmentResult(getCertificates(store.getCertificates(new X509CertStoreSelector())));
		} catch (RequestPendingException e) {
			Callable<EnrollmentResult> task = new PendingEnrollmentTask(transport, ca, keyPair, identity, digestAlgorithm);
			
			return new EnrollmentResult(task);
		} catch (EnrollmentFailureException e) {
			return new EnrollmentResult(e.getMessage());
		} catch (CertStoreException e) {
			RuntimeException rt = new RuntimeException(e);
			LOGGER.throwing(getClass().getName(), "parse", rt);
			throw rt;
		}
	}
}
