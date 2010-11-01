/*
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

import org.bouncycastle.asn1.cms.SignedData;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

public class CertRep extends PkiResponse<SignedData> {

	public CertRep(TransactionId transId, Nonce senderNonce, Nonce recipientNonce, PkiStatus pkiStatus, SignedData messageData) {
		// SUCCESS
		super(transId, MessageType.CertRep, senderNonce, recipientNonce, pkiStatus, messageData);
	}
	
	public CertRep(TransactionId transId, Nonce senderNonce, Nonce recipientNonce, PkiStatus pkiStatus, FailInfo failInfo) {
		// FAILURE
		super(transId, MessageType.CertRep, senderNonce, recipientNonce, pkiStatus, failInfo);
	}
	
	public CertRep(TransactionId transId, Nonce senderNonce, Nonce recipientNonce, PkiStatus pkiStatus) {
		// PENDING
		super(transId, MessageType.CertRep, senderNonce, recipientNonce, pkiStatus);
	}
}
