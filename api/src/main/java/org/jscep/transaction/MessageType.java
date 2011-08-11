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
 * This class represents the SCEP <code>messageType</code> attribute.
 * 
 * @author David Grant
 */
public enum MessageType {
	/**
	 * Response to certificate or CRL request
	 */
	CertRep(3),
	/**
	 * PKCS #10 certificate request
	 */
	PKCSReq(19),
	/**
	 * Certificate polling in manual enrollment
	 */
	GetCertInitial(20),
	/**
	 * Retrieve a certificate
	 */
	GetCert(21),
	/**
	 * Retrieve a CRL
	 */
	GetCRL(22);
	
	private final int value;
	
	private MessageType(int value) {
    	this.value = value;
    }
	
    public int getValue() {
    	return value;
    }
    
    public static MessageType valueOf(int value) {
    	for (MessageType msgType : MessageType.values()) {
    		if (msgType.getValue() == value) {
    			return msgType;
    		}
    	}
    	throw new IllegalArgumentException();
    }
    
    @Override
    public String toString() {
    	return name();
    }
}
