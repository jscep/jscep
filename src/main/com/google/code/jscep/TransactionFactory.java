package com.google.code.jscep;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import com.google.code.jscep.transport.Transport;

public final class TransactionFactory {
	private TransactionFactory() {
	}
	
	public static Transaction createTransaction(Transport transport) {
		return createTransaction(transport, null);
	}
	
	public static Transaction createTransaction(Transport transport, X509Certificate ca) {
		return createTransaction(transport, ca, null);
	}
	
	public static Transaction createTransaction(Transport transport, X509Certificate ca, KeyPair keyPair) {
		return new Transaction(transport, ca, keyPair);
	}
}
