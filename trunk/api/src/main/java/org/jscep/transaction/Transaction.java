package org.jscep.transaction;

import java.io.IOException;
import java.security.cert.CertStore;

import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transport.Transport;

public abstract class Transaction {
	protected final PkiMessageEncoder encoder;
	protected final PkiMessageDecoder decoder;
	protected State state;
	protected FailInfo failInfo;
	protected CertStore certStore;
	
	public Transaction(PkiMessageEncoder encoder, PkiMessageDecoder decoder) {
		this.encoder = encoder;
		this.decoder = decoder;
	}
	/**
	 * Retrieve the reason for failure.
	 * 
	 * @return the reason for failure.
	 */
	public FailInfo getFailInfo() {
		if (state != State.CERT_NON_EXISTANT) {
			throw new IllegalStateException();
		}
		return failInfo;
	}
	
	public CertStore getCertStore() {
		if (state != State.CERT_ISSUED) {
			throw new IllegalStateException();
		}
		return certStore;
	}
	
	public State getState() {
		return state;
	}
	
	public abstract State send(Transport transport) throws IOException;
	public abstract TransactionId getId();
	
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
		 * Clients should use {@link Transaction#getCertStore()} to 
		 * retrieve the enrolled certificates.
		 */
		CERT_ISSUED,
	}
}
