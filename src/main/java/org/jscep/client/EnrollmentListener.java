package org.jscep.client;

import java.security.cert.CertStore;

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.TransactionId;

public interface EnrollmentListener {
	void onSuccess(TransactionId transId, CertStore store);
	void onPending(TransactionId transId);
	void onFailure(TransactionId transId, FailInfo info);
}
