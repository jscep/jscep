package com.google.code.jscep;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;

public class EnrollmentResult {
	private List<X509Certificate> certs;
	private Callable<EnrollmentResult> task;
	
	public EnrollmentResult(List<X509Certificate> certs) {
		this.certs = certs;
	}
	
	public EnrollmentResult(Callable<EnrollmentResult> task) {
		this.task = task;
	}
	
	public List<X509Certificate> getCertificates() {
		return certs;
	}
	
	public Callable<EnrollmentResult> getTask() {
		return task;
	}
	
	public boolean isPending() {
		return certs == null; 
	}
	
	public boolean isComplete() {
		return task == null;
	}
}
