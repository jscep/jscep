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

import org.jscep.content.ScepContentHandler;
import org.jscep.response.Capabilities;

/**
 * This class represents a <code>GetCACaps</code> request.
 * 
 * @author David Grant
 */
public final class GetCaCaps extends Request<Capabilities> {
	private final String caIdentifier;

	public GetCaCaps(ScepContentHandler<Capabilities> handler) {
		this(null, handler);
	}
	
	public GetCaCaps(String caIdentifier, ScepContentHandler<Capabilities> handler) {
		super(Operation.GetCACaps, handler);
		this.caIdentifier = caIdentifier;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getMessage() {
		if (caIdentifier == null) {
			return "";
		}
		return caIdentifier;
	}
	
	@Override
	public String toString() {
		if (caIdentifier != null) {
			return "GetCACaps(" + caIdentifier + ")";
		} else {
			return "GetCACaps";
		}
	}
}
