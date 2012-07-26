package org.jscep.client;

import java.security.cert.CertStore;

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.TransactionId;

public class CapturingEnrollmentListener extends EnrollmentListenerSupport {
	private CertStore certStore;
	private FailInfo failInfo;
	
	@Override
	public void onSuccess(TransactionId transId, CertStore certStore) {
		this.certStore = certStore;
	}

	@Override
	public void onFailure(TransactionId transId, FailInfo info) {
		this.failInfo = info;
	}
	
	public CertStore getCertStore() {
		return certStore;
	}
	
	public FailInfo getFailInfo() {
		return failInfo;
	}
	
}
