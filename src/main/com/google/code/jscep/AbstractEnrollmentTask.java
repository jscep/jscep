package com.google.code.jscep;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

abstract public class AbstractEnrollmentTask implements Callable<EnrollmentResult> {
	abstract public EnrollmentResult call() throws Exception;
	
	protected List<X509Certificate> getCertificates(Collection<? extends Certificate> certs) {
		List<X509Certificate> x509 = new ArrayList<X509Certificate>();
		
		for (Certificate cert : certs) {
			x509.add((X509Certificate) cert);
		}
		
		return x509;
	}

}