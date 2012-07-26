package org.jscep.client;

import java.security.cert.CertStore;

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.TransactionId;

public abstract class EnrollmentListenerSupport implements EnrollmentListener {

	public void onSuccess(TransactionId transId, CertStore store) {
		// noop
	}

	public void onPending(TransactionId transId) {
		// noop
	}

	public void onFailure(TransactionId transId, FailInfo info) {
		// noop
	}

}
