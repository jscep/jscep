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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

public class CertRep extends PkiResponse<DEROctetString> {

	public CertRep(TransactionId transId, Nonce senderNonce, Nonce recipientNonce, DEROctetString messageData) {
		// SUCCESS
		super(transId, MessageType.CertRep, senderNonce, recipientNonce, PkiStatus.SUCCESS, messageData);
	}
	
	public CertRep(TransactionId transId, Nonce senderNonce, Nonce recipientNonce, FailInfo failInfo) {
		// FAILURE
		super(transId, MessageType.CertRep, senderNonce, recipientNonce, PkiStatus.FAILURE, failInfo);
	}
	
	public CertRep(TransactionId transId, Nonce senderNonce, Nonce recipientNonce) {
		// PENDING
		super(transId, MessageType.CertRep, senderNonce, recipientNonce, PkiStatus.PENDING);
	}
	
	public static <T extends ASN1Encodable> CertRep createResponse(PkiRequest<T> req, DEROctetString messageData) {
		Nonce senderNonce = Nonce.nextNonce();
		
		return new CertRep(req.getTransactionId(), senderNonce, req.getSenderNonce(), messageData);
	}
	
	public static <T extends ASN1Encodable> CertRep createResponse(PkiRequest<T> req, FailInfo failInfo) {
		Nonce senderNonce = Nonce.nextNonce();
		
		return new CertRep(req.getTransactionId(), senderNonce, req.getSenderNonce(), failInfo);
	}
	
	public static <T extends ASN1Encodable> CertRep createResponse(PkiRequest<T> req) {
		Nonce senderNonce = Nonce.nextNonce();
		
		return new CertRep(req.getTransactionId(), senderNonce, req.getSenderNonce());
	}
	
	public CMSSignedData getCMSSignedData() throws CMSException {
		return new CMSSignedData(getMessageData().getOctets());
	}
}
