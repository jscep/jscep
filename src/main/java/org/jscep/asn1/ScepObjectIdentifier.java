/**
 * Copyright (c) 2009-2012 David Grant
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
package org.jscep.asn1;

/**
 * Object Identifiers used by SCEP.
 * 
 * @author David Grant
 */
public enum ScepObjectIdentifier {
    /**
     * <code>2.16.840.1.113733.1.9.2</code>
     */
    MESSAGE_TYPE("2.16.840.1.113733.1.9.2"),
    /**
     * <code>2.16.840.1.113733.1.9.3</code>
     */
    PKI_STATUS("2.16.840.1.113733.1.9.3"),
    /**
     * <code>2.16.840.1.113733.1.9.4</code>
     */
    FAIL_INFO("2.16.840.1.113733.1.9.4"),
    /**
     * <code>2.16.840.1.113733.1.9.5</code>
     */
    SENDER_NONCE("2.16.840.1.113733.1.9.5"),
    /**
     * <code>2.16.840.1.113733.1.9.6</code>
     */
    RECIPIENT_NONCE("2.16.840.1.113733.1.9.6"),
    /**
     * <code>2.16.840.1.113733.1.9.7</code>
     */
    TRANS_ID("2.16.840.1.113733.1.9.7");

    private final String objId;

    ScepObjectIdentifier(final String objId) {
	this.objId = objId;
    }

    /**
     * Returns the ObjectIdentifier as a String.
     * 
     * @return the ObjectIdentifier
     */
    public String id() {
	return objId;
    }
}
