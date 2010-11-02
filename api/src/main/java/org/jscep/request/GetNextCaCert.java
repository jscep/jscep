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

import java.security.cert.X509Certificate;
import java.util.List;

import org.jscep.content.ScepContentHandler;


/**
 * This class represents a <code>GetNextCACert</code> request.
 * 
 * @author David Grant
 */
public class GetNextCaCert extends Request<List<X509Certificate>> {
    private final String caIdentifier;

    /**
     * Creates a new GetNextCACert request with the given CA identification string.
     * 
     * @param issuer the existing CA certificate.
     * @param caIdentifier the CA identification string.
     */
    public GetNextCaCert(String caIdentifier, ScepContentHandler<List<X509Certificate>> handler) {
    	super(Operation.GetNextCACert, handler);
        this.caIdentifier = caIdentifier;
    }
    
    public GetNextCaCert(ScepContentHandler<List<X509Certificate>> handler) {
    	this(null, handler);
    }

    /**
     * {@inheritDoc}
     */
    public String getMessage() {
        return caIdentifier;
    }
    
    @Override
	public String toString() {
    	if (caIdentifier != null) {
    		return "GetNextCACert(" + caIdentifier + ")";
    	} else {
    		return "GetNextCACert";
    	}
	}
}
