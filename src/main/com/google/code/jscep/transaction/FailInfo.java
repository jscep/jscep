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

/**
 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-3.1.1.4
 */
public enum FailInfo {
    badAlg(0, "Unrecognized or unsupported algorithm identifier"),
    badMessageCheck(1, "Integrity check failed"),
    badRequest(2, "Transaction not permitted or supported"),
    badTime(3, "The signingTime attribute from the PKCS#7 SignedAttributes was not sufficiently close to the system time"),
    badCertId(4, "No certificate could be identified matching the provided criteria");
    
    private final int value;
    private final String desc;
	
	private FailInfo(int value, String desc) {
    	this.value = value;
    	this.desc = desc;
    }
	
    private int getValue() {
    	return value;
    }
    
    @Override
    public String toString() {
    	return desc;
    }
    
    public static FailInfo valueOf(int value) {
    	for (FailInfo failInfo : FailInfo.values()) {
    		if (failInfo.getValue() == value) {
    			return failInfo;
    		}
    	}
    	throw new IllegalArgumentException();
    }
}
