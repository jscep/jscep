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

package com.google.code.jscep;

import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

import com.google.code.jscep.request.PkcsReq;
import com.google.code.jscep.request.PkiOperation;
import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.transaction.TransactionFactory;
import com.google.code.jscep.transport.Transport;

public class InitialEnrollmentTask extends AbstractEnrollmentTask {
	private final Transport transport;
	private final X509Certificate ca;
	private final KeyPair keyPair;
	private final X509Certificate identity;
	private final char[] password;
	
	public InitialEnrollmentTask(Transport transport, X509Certificate ca, KeyPair keyPair, X509Certificate identity, char[] password) {
		this.transport = transport;
		this.ca = ca;
		this.keyPair = keyPair;
		this.identity = identity;
		this.password = password;
	}
	
	@Override
	public EnrollmentResult call() throws Exception {
		Transaction trans = TransactionFactory.createTransaction(transport, ca, identity, keyPair);
		PkiOperation req = new PkcsReq(keyPair, identity, password);
		try {
			CertStore store = trans.performOperation(req);
			
			return new EnrollmentResult(getCertificates(store.getCertificates(null)));
		} catch (RequestPendingException e) {
			Callable<EnrollmentResult> task = new PendingEnrollmentTask(transport, ca, keyPair, identity);
			
			return new EnrollmentResult(task);
		}
	}
}
