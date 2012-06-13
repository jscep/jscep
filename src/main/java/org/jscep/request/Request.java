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
 * This interface represents a SCEP request.
 * <p/>
 * Once an instance of a <code>Request</code> implementation has been obtained,
 * it can be sent to a SCEP server by using an instance of
 * {@link org.jscep.transport.Transport}.
 *
 * @author David Grant
 * @see org.jscep.transport.Transport#sendRequest(Request, org.jscep.content.ScepContentHandler)
 */
public abstract class Request {
    private final Operation operation;

    public Request(Operation operation) {
        this.operation = operation;
    }

    /**
     * Returns the name of this operation.
     *
     * @return the name of this operation.
     */
    public Operation getOperation() {
        return operation;
    }

    /**
     * Returns the message for this request.
     *
     * @return the message.
     */
    public abstract String getMessage();
}
