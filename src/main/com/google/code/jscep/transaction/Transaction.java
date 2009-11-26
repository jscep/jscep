/*
 * Copyright (c) 2009 David Grant
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

package com.google.code.jscep.transaction;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;

import com.google.code.jscep.RequestFailureException;
import com.google.code.jscep.RequestPendingException;
import com.google.code.jscep.operations.PkiOperation;
import com.google.code.jscep.request.PkiRequest;
import com.google.code.jscep.response.PkiMessage;
import com.google.code.jscep.transport.Transport;

public class Transaction {
    private final TransactionId transId;
    private final Nonce senderNonce;
    private final KeyPair keyPair;
    private final Transport transport;
    private final Enveloper enveloper;
    private final Signer signer;
    
    protected Transaction(Transport transport, KeyPair keyPair, Enveloper enveloper, Signer signer) {
    	this.transport = transport;
    	this.keyPair = keyPair;
        this.transId = TransactionId.createTransactionId(keyPair);
        this.senderNonce = NonceFactory.nextNonce();
        this.enveloper = enveloper;
        this.signer = signer;
    }

    public CertStore performOperation(PkiOperation operation) throws MalformedURLException, IOException, CmsException, RequestPendingException, RequestFailureException {
    	try {
    		byte[] enveloped = enveloper.envelope(operation.getMessageData());
	        byte[] signedData = signer.sign(enveloped, operation.getMessageType(), this.transId, this.senderNonce);
	        PkiRequest request = new PkiRequest(signedData);
	        byte[] response = (byte[]) transport.sendMessage(request);
    	
	        return handleResponse(response);
    	} catch (GeneralSecurityException e) {
    		throw new CmsException(e);
    	}
    }
    
    public CertStore handleResponse(byte[] bytes) throws CmsException, RequestPendingException, RequestFailureException, NoSuchProviderException, NoSuchAlgorithmException {
    	PkiMessage msg = PkiMessage.getInstance(keyPair, bytes);

        if (msg.getTransactionId().equals(this.transId) == false) {
            throw new CmsException("Transaction ID Mismatch: Sent [" + this.transId + "]; Received [" + msg.getTransactionId() + "]");
        }
        
        if (msg.getRecipientNonce().equals(senderNonce) == false) {
        	throw new CmsException("Sender Nonce Mismatch.  Sent [" + this.senderNonce + "]; Received [" + msg.getRecipientNonce() + "]");
        }
        
        // TODO: Detect replay attacks.
        // 
        // http://tools.ietf.org/html/draft-nourse-scep-19#section-8.5
        msg.getSenderNonce();
        
        if (msg.getStatus().equals(PkiStatus.FAILURE)) {
        	throw new RequestFailureException(msg.getFailInfo().toString());
        } else if (msg.getStatus().equals(PkiStatus.PENDING)) {
        	throw new RequestPendingException();
        } else {
        	return msg.getCertStore();
        }
    }
}
