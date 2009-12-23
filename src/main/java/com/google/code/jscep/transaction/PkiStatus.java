/*
 * Copyright (c) 2009 David Grant
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

package com.google.code.jscep.transaction;

import java.util.logging.Logger;

/**
 * This class represents the <tt>SCEP</tt> <tt>pkiStatus</tt> attribute.
 * 
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-3.1.1.3">SCEP Internet-Draft Reference</a>
 */
public enum PkiStatus {
	/**
	 * Request granted
	 */
    SUCCESS(0),
    /**
     * Request rejected
     */
    FAILURE(2),
    /**
     * Request pending for manual approval
     */
    PENDING(3);
    
    private static Logger LOGGER = Logger.getLogger("com.google.code.jscep.transaction");
    private final int value;
    
    private PkiStatus(int value) {
    	this.value = value;
    }
    
    public int getValue() {
    	return value;
    }
    
    public static PkiStatus valueOf(int value) {
    	for (PkiStatus status : PkiStatus.values()) {
    		if (status.getValue() == value) {
    			return status;
    		}
    	}
    	throw new IllegalArgumentException();
    }
}
