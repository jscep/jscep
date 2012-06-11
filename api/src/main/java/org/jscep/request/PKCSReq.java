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
package org.jscep.request;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Base64;

/**
 * This class represents a <code>PKCSReq</code> request.
 * 
 * @author David Grant
 */
public class PKCSReq extends Request<CMSSignedData> {
	private final CMSSignedData msgData;

	/**
	 * Creates a new instance of this class using the provided pkiMessage
	 * and response handler.
	 * 
	 * @param msgData the pkiMessage to use.
	 * @param handler the response handler for this request.
	 */
	public PKCSReq(CMSSignedData msgData) {
		super(Operation.PKIOperation);
		
		this.msgData = msgData;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getMessage() throws IOException {
		byte[] bytes = Base64.encode(msgData.getEncoded());
		
		return new String(bytes);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void write(OutputStream out) throws IOException {
    	out.write(msgData.getEncoded());
    }
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return msgData.toString();
	}
}
