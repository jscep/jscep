package com.google.code.jscep;

public class ScepException extends Exception {
	/**
	 * Serial Version
	 */
	private static final long serialVersionUID = 2603468486730081206L;

	public ScepException() {
	}
	
	public ScepException(String message) {
		super(message);
	}
	
	public ScepException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public ScepException(Throwable cause) {
		super(cause);
	}
}
