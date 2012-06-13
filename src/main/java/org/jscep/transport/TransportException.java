package org.jscep.transport;

public class TransportException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 7384278241045962726L;

	public TransportException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public TransportException(Throwable cause) {
		super(cause);
	}
	
	public TransportException(String message) {
		super(message);
	}
}
