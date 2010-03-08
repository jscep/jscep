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
package org.jscep.request;

import java.io.IOException;
import java.security.KeyPair;

import org.jscep.content.CertRepContentHandler;
import org.jscep.pkcs7.PkiMessage;


/**
 * This class represents a <code>PKCSReq</code> request.
 * 
 * @author David Grant
 */
public class PkcsReq implements Request<PkiMessage> {
	private final PkiMessage msgData;
	private final KeyPair keyPair;

	/**
	 * Creates a new instance of this class using the provided pkiMessage
	 * and {@link java.security.KeyPair}.
	 * 
	 * @param msgData the pkiMessage to use.
	 * @param keyPair the KeyPair to use.
	 */
	public PkcsReq(PkiMessage msgData, KeyPair keyPair) {
		this.msgData = msgData;
		this.keyPair = keyPair;
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] getMessage() throws IOException {
		return msgData.getEncoded();
	}

	/**
	 * {@inheritDoc}
	 */
	public Operation getOperation() {
		return Operation.PKIOperation;
	}

	/**
	 * {@inheritDoc}
	 */
	public CertRepContentHandler getContentHandler() {
		return new CertRepContentHandler(keyPair);
	}
	
	@Override
	public String toString() {
		return msgData.toString();
	}
}
