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

import java.security.cert.X509Certificate;
import java.util.List;

import org.jscep.content.NextCaCertificateContentHandler;


/**
 * This class represents a <code>GetNextCACert</code> request.
 * 
 * @author David Grant
 */
public class GetNextCACert implements Request<List<X509Certificate>> {
    private final String caIdentifier;
    private final X509Certificate issuer;

    /**
     * Creates a new GetNextCACert request with the given CA identification string.
     * 
     * @param issuer the existing CA certificate.
     * @param caIdentifier the CA identification string.
     */
    public GetNextCACert(X509Certificate issuer, String caIdentifier) {
    	this.issuer = issuer;
        this.caIdentifier = caIdentifier;
    }
    
    public GetNextCACert(X509Certificate issuer) {
    	this.issuer = issuer;
        this.caIdentifier = null;
    }

    /**
     * {@inheritDoc}
     */
    public Operation getOperation() {
        return Operation.GetNextCACert;
    }

    /**
     * {@inheritDoc}
     */
    public String getMessage() {
        return caIdentifier;
    }
     
    /**
     * {@inheritDoc}
     */
    public NextCaCertificateContentHandler getContentHandler() {
    	return new NextCaCertificateContentHandler(issuer);
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
