package org.jscep.transaction;

import java.security.cert.CertStore;
import java.util.concurrent.Callable;

public interface Transaction {
	/**
	 * Returns the current state of this transaction.
	 * 
	 * @return the current state.
	 */
	State getState();
	/**
	 * Retrieve the reason for failure.
	 * 
	 * @return the reason for failure.
	 */
	FailInfo getFailureReason();
	CertStore getCertStore();
	Callable<State> getTask();
	
	/**
	 * This class represents the state of a transaction.
	 * 
	 * @author David Grant
	 */
	public enum State {
		/**
		 * The transaction is a pending state.
		 * <p>
		 * Clients should use {@link Transaction#getTask()} to retrieve
		 * the task to execute in order to proceed.
		 */
		CERT_REQ_PENDING,
		/**
		 * The transaction is in a failed state.
		 * <p>
		 * Clients should use {@link Transaction#getFailureReason()} to retrieve
		 * the failure reason.
		 */
		CERT_NON_EXISTANT,
		/**
		 * The transaction has succeeded.
		 * <p>
		 * Clients should use {@link Transaction#getIssuedCertificates()} to 
		 * retrieve the enrolled certificates.
		 */
		CERT_ISSUED,
	}
}
