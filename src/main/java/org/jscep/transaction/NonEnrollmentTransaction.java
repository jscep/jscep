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
package org.jscep.transaction;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.content.CertRepContentHandler;
import org.jscep.content.InvalidContentException;
import org.jscep.content.InvalidContentTypeException;
import org.jscep.message.CertRep;
import org.jscep.message.GetCRL;
import org.jscep.message.GetCert;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.message.PkiRequest;
import org.jscep.request.PKCSReq;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
import org.jscep.util.CertStoreUtils;

public class NonEnrollmentTransaction extends Transaction {
    private final TransactionId transId;
    private final PkiRequest<? extends ASN1Encodable> request;

    public NonEnrollmentTransaction(Transport transport, PkiMessageEncoder encoder, PkiMessageDecoder decoder, IssuerAndSerialNumber iasn, MessageType msgType) {
        super(transport, encoder, decoder);
        this.transId = TransactionId.createTransactionId();

        if (msgType == MessageType.GET_CERT) {
            this.request = new GetCert(transId, Nonce.nextNonce(), iasn);
        } else if (msgType == MessageType.GET_CRL) {
            this.request = new GetCRL(transId, Nonce.nextNonce(), iasn);
        } else {
            throw new IllegalArgumentException(msgType.toString());
        }
    }

    public TransactionId getId() {
        return transId;
    }

    public State send() throws IOException, TransportException {
    	final CertRepContentHandler handler = new CertRepContentHandler();
        final byte[] signedData = encoder.encode(request);
        byte[] inMsg;
		try {
			inMsg = transport.sendRequest(new PKCSReq(signedData), handler);
		} catch (InvalidContentTypeException e) {
			throw ioe(e);
		} catch (InvalidContentException e) {
			throw ioe(e);
		}
        final CertRep response = (CertRep) decoder.decode(inMsg);

        if (response.getPkiStatus() == PkiStatus.FAILURE) {
            failInfo = response.getFailInfo();
            state = State.CERT_NON_EXISTANT;
        } else if (response.getPkiStatus() == PkiStatus.SUCCESS) {
            try {
                CMSSignedData responseSd = new CMSSignedData(response.getMessageData());
                
                certStore = CertStoreUtils.fromSignedData(responseSd);
            } catch (CMSException e) {
                throw ioe(e);
            }
            state = State.CERT_ISSUED;
        } else {
            throw new IOException("Invalid Response");
        }

        return state;
    }

	private IOException ioe(Throwable t) {
		IOException ioe = new IOException();
		ioe.initCause(t);
		
		return ioe;
	}
}
