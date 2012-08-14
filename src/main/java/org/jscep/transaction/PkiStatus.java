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
 * This class represents the SCEP <code>pkiStatus</code> attribute.
 * 
 * @author David Grant
 */
public enum PkiStatus {
    /**
     * Request granted
     */
    SUCCESS(0),
    /**
     * Request rejected
     */
    FAILURE(2),
    /**
     * Request pending for manual approval
     */
    PENDING(3);

    private final int value;

    private PkiStatus(int value) {
	this.value = value;
    }

    public int getValue() {
	return value;
    }

    public static PkiStatus valueOf(int value) {
	for (PkiStatus status : PkiStatus.values()) {
	    if (status.getValue() == value) {
		return status;
	    }
	}
	throw new IllegalArgumentException();
    }

    @Override
    public String toString() {
	return name();
    }
}
