package org.jscep.client;

import java.security.cert.CertStore;

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.TransactionId;

public final class EnrolmentResponse {
	private final FailInfo failInfo;
	private final CertStore certStore;
	private final TransactionId transId;
	/**
	 * Constructs a new instance of this class to represent a pending response.
	 * @param transId the transaction ID
	 */
	public EnrolmentResponse(TransactionId transId) {
		this(transId, null, null);
	}
	/**
	 * Constructs a new instance of this class to represent a failure response.
	 * @param transId the transaction ID
	 * @param failInfo the failure reason
	 */
	public EnrolmentResponse(TransactionId transId, FailInfo failInfo) {
		this(transId, null, failInfo);
	}
	/**
	 * Constructs a new instance of this class to represent a success response.
	 * @param transId the transaction ID
	 * @param certStore the certificate response
	 */
	public EnrolmentResponse(TransactionId transId, CertStore certStore) {
		this(transId, certStore, null);
	}
	
	private EnrolmentResponse(TransactionId transId, CertStore certStore, FailInfo failInfo) {
		this.transId = transId;
		this.certStore = certStore;
		this.failInfo = failInfo;
	}

	public boolean isPending() {
		return failInfo == null && certStore == null;
	}
	public boolean isFailure() {
		return failInfo != null;
	}
	public boolean isSuccess() {
		return certStore != null;
	}
	public TransactionId getTransactionId() {
		return transId;
	}
	public CertStore getCertStore() {
		if (isSuccess()) {
			return certStore;
		}
		throw new IllegalStateException();
	}
	public FailInfo getFailInfo() {
		if (isFailure()) {
			return failInfo;
		}
		throw new IllegalStateException();
	}

}
