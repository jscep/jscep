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

package com.google.code.jscep.pkcs7;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;


/**
 * Implementation of {@link PkcsPkiEnvelope} that uses Bouncy Castle.
 */
public class PkcsPkiEnvelopeImpl extends ContentInfo implements PkcsPkiEnvelope {
	private ASN1Encodable msgData;
	private byte[] encoded;
	
	PkcsPkiEnvelopeImpl(EnvelopedData data) {
		super(CMSObjectIdentifiers.envelopedData, data);
	}
	
	void setMessageData(ASN1Encodable msgData) {
		this.msgData = msgData;
	}
	
	public ASN1Encodable getMessageData() {
		return msgData;
	}
	
	public byte[] getEncoded() {
		return encoded;
	}
	
	void setEncoded(byte[] encoded) {
		this.encoded = encoded;
	}
	
	public EnvelopedData getContent() {
		return (EnvelopedData) super.getContent();
	}
}
