package com.google.code.jscep;

public class RequestPendingException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = -2249313758831908719L;

	public RequestPendingException() {
	}
	
	public RequestPendingException(String message) {
		super(message);
	}
	
	public RequestPendingException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public RequestPendingException(Throwable cause) {
		super(cause);
	}
}
