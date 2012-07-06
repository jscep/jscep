/*
 * Copyright (c) 2009-2012 David Grant
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

/**
 * This class represents a <code>GetCACert</code> request.
 * 
 * @author David Grant
 */
public final class GetCaCert extends Request {
    private final String caIdentifier;

    /**
     * Creates a new GetCACert request with the given CA identification string.
     * 
     * @param caIdentifier
     *            the CA identification string.
     */
    public GetCaCert(String caIdentifier) {
        super(Operation.GET_CA_CERT);

        this.caIdentifier = caIdentifier;
    }

    public GetCaCert() {
        this(null);
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
            return "GetCACert(" + caIdentifier + ")";
        } else {
            return "GetCACert";
        }
    }
}
