package org.jscep.transaction;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;

public interface Transaction {
	State getState();
	FailInfo getFailureReason();
	List<X509Certificate> getCertificates() throws IOException;
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
