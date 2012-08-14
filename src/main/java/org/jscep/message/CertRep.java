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
package org.jscep.message;

import org.bouncycastle.cms.CMSSignedData;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

/**
 * This class represents a <tt>CertRep</tt> <tt>pkiMessage</tt>.
 */
public final class CertRep extends PkiResponse<CMSSignedData> {
    /**
     * Creates a new CertRep to indicate <em>success</em> state.
     * 
     * @param transId
     *            the transaction ID
     * @param senderNonce
     *            the sender nonce
     * @param recipientNonce
     *            the recipient nonce
     * @param messageData
     *            the message data
     */
    public CertRep(TransactionId transId, Nonce senderNonce,
	    Nonce recipientNonce, CMSSignedData messageData) {
	super(transId, MessageType.CERT_REP, senderNonce, recipientNonce,
		PkiStatus.SUCCESS, messageData, null);
    }

    /**
     * Creates a new CertRep to indicate <em>failure</em> state.
     * 
     * @param transId
     *            the transaction ID
     * @param senderNonce
     *            the sender nonce
     * @param recipientNonce
     *            the recipient nonce
     * @param failInfo
     *            the fail info enum
     */
    public CertRep(TransactionId transId, Nonce senderNonce,
	    Nonce recipientNonce, FailInfo failInfo) {
	super(transId, MessageType.CERT_REP, senderNonce, recipientNonce,
		PkiStatus.FAILURE, null, failInfo);
    }

    /**
     * Creates a new CertRep to indicate <em>pending</em> state.
     * 
     * @param transId
     *            the transaction ID
     * @param senderNonce
     *            the sender nonce
     * @param recipientNonce
     *            the recipient nonce
     */
    public CertRep(TransactionId transId, Nonce senderNonce,
	    Nonce recipientNonce) {
	super(transId, MessageType.CERT_REP, senderNonce, recipientNonce,
		PkiStatus.PENDING, null, null);
    }
}
