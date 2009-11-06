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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.util.Hashtable;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.util.encoders.Hex;

import com.google.code.jscep.asn1.ScepObjectIdentifiers;
import com.google.code.jscep.request.PkiOperation;
import com.google.code.jscep.request.PkiRequest;
import com.google.code.jscep.transport.Transport;

/**
 * Please refactor me.  I have far too many responsibilities.
 * 
 * Break dependency on BC into seperate classes.
 */
public class Transaction {
    private static final AtomicLong COUNTER = new AtomicLong();
    private final DERPrintableString transId;
    private DEROctetString senderNonce;
    private int reason;
    private final KeyPair keyPair;
    private final Transport transport;
    private final Enveloper enveloper;
    private final Signer signer;
    
    protected Transaction(Transport transport, KeyPair keyPair, Enveloper enveloper, Signer signer) {
    	this.transport = transport;
    	this.keyPair = keyPair;
        this.transId = generateTransactionId();
        this.senderNonce = generateSenderNonce();
        this.enveloper = enveloper;
        this.signer = signer;
    }
    
    private DEROctetString generateSenderNonce() {
    	return new DEROctetString(NonceFactory.nextNonce().getBytes());
    }
    
    private DERPrintableString generateTransactionId() {
    	if (keyPair == null) {
    		return new DERPrintableString(Long.toHexString(COUNTER.getAndIncrement()).getBytes());
    	} else {
	    	MessageDigest digest = null;
	        try {
	            digest = MessageDigest.getInstance("MD5");
	        } catch (NoSuchAlgorithmException e) {
	            throw new RuntimeException(e);
	        }
	        return new DERPrintableString(Hex.encode(digest.digest(keyPair.getPublic().getEncoded())));
    	}
    }
    
    public int getFailureReason() {
    	return reason;
    }

    public CertStore performOperation(PkiOperation operation) throws MalformedURLException, IOException, CmsException {
    	try {
    		byte[] enveloped = enveloper.envelope(operation.getMessageData());
	
	        Attribute msgType = getMessageTypeAttribute(operation);
	        Attribute transId = getTransactionIdAttribute();
	        Attribute senderNonce = getSenderNonceAttribute();
	
	        Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>();
	        attributes.put(msgType.getAttrType(), msgType);
	        attributes.put(transId.getAttrType(), transId);
	        attributes.put(senderNonce.getAttrType(), senderNonce);
	        AttributeTable table = new AttributeTable(attributes);
	
	        byte[] signedData = signer.sign(enveloped, table);
	        PkiRequest request = new PkiRequest(signedData);
	        byte[] response = (byte[]) transport.sendMessage(request);
    	
	        return handleResponse(response);
    	} catch (GeneralSecurityException e) {
    		throw new CmsException(e);
    	}
    }
    
    private Attribute getMessageTypeAttribute(PkiOperation operation) {
        return new Attribute(ScepObjectIdentifiers.messageType, new DERSet(operation.getMessageType()));
    }
    

    private Attribute getTransactionIdAttribute() {
        return new Attribute(ScepObjectIdentifiers.transId, new DERSet(transId));
    }

    private Attribute getSenderNonceAttribute() {
        return new Attribute(ScepObjectIdentifiers.senderNonce, new DERSet(senderNonce));
    }
    
    public CertStore handleResponse(byte[] bytes) throws CmsException {
    	CmsResponseParser parser = new CmsResponseParser(transId, senderNonce, keyPair);
    	
    	return parser.handleResponse(bytes);
    }
}
