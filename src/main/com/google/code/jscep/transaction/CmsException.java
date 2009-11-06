package com.google.code.jscep.transaction;

import com.google.code.jscep.ScepException;

public class CmsException extends ScepException {
	/**
	 * Serial Version
	 */
	private static final long serialVersionUID = -7553545517514690987L;

	public CmsException() {
	}
	
	public CmsException(String message) {
		super(message);
	}
	
	public CmsException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public CmsException(Throwable cause) {
		super(cause);
	}
}
