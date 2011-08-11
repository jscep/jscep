/*
 * Copyright (c) 2009-2010 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
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
package org.jscep.transaction;


/**
 * This class represents the SCEP <code>failInfo</code> attribute.
 * 
 * @author David Grant
 */
public enum FailInfo {
	/**
	 * Unrecognized or unsupported algorithm identifier
	 */
    badAlg(0, "Unrecognized or unsupported algorithm identifier"),
    /**
     * Integrity check failed
     */
    badMessageCheck(1, "Integrity check failed"),
    /**
     * Transaction not permitted or supported
     */
    badRequest(2, "Transaction not permitted or supported"),
    /**
     * The signingTime attribute from the PKCS#7 SignedAttributes was not sufficiently close to the system time
     */
    badTime(3, "The signingTime attribute from the PKCS#7 SignedAttributes was not sufficiently close to the system time"),
    /**
     * No certificate could be identified matching the provided criteria
     */
    badCertId(4, "No certificate could be identified matching the provided criteria");
    
    private final int value;
    private final String desc;
	
	private FailInfo(int value, String desc) {
    	this.value = value;
    	this.desc = desc;
    }
	
    public int getValue() {
    	return value;
    }
    
    public String getDescription() {
    	return desc;
    }
    
    @Override
    public String toString() {
    	return name();
    }
    
    
    public static FailInfo valueOf(int value) {
    	for (FailInfo failInfo : FailInfo.values()) {
    		if (failInfo.getValue() == value) {
    			return failInfo;
    		}
    	}
    	// Fall back to bad request (see issue 39).
    	return FailInfo.badRequest;
    }
}
