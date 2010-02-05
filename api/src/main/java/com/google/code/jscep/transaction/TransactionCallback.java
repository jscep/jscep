package com.google.code.jscep.transaction;

import java.security.cert.CertStore;

public interface TransactionCallback {
	void onSuccess(CertStore certStore);
	void onFailure(FailInfo failInfo);
	long onPending(long previousDelay);
	void onException(Exception e);
}
