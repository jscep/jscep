/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.google.code.jscep;

import com.google.code.jscep.transaction.FailInfo;

/**
 * This exception represents the situation where a PKI operation has failed.
 * 
 * @author David Grant
 */
public class PKIOperationFailureException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 747055232323410404L;
	private final FailInfo failInfo;

	/**
	 * Creates a new instance of <code>PKIOperationFailureException</code> from
	 * the provided {@link FailInfo}.
	 * <p>
	 * 
	 * @param failInfo the failure reason.
	 */
	public PKIOperationFailureException(FailInfo failInfo) {
		super(failInfo.toString());
		
		this.failInfo = failInfo;
	}
	
	public FailInfo getFailInfo() {
		return failInfo;
	}
}
