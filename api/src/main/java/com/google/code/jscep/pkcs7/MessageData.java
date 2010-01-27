/*
 * Copyright (c) 2009-2010 David Grant
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

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;

/**
 * This class represents the SCEP <code>messageData</code> data structure. 
 * 
 * @author davidjgrant1978
 */
public class MessageData {
	private final ContentInfo contentInfo;
	
	/**
	 * Creates a new instance of MessageData using the provided ContentInfo.
	 * 
	 * @param contentInfo the ContentInfo.
	 */
	private MessageData(ContentInfo contentInfo) {
		this.contentInfo = contentInfo;
	}
	
	/**
	 * Returns the object wrapped in this MessageData.
	 * 
	 * @return the wrapped object.
	 */
	public ASN1Encodable getContent() {
		return (ASN1Encodable) contentInfo.getContent();
	}
	
	/**
	 * Provides a new instance of MessageData by wrapping the provided object.
	 * 
	 * @param content the object to wrap.
	 * @return a new instance of MessageData.
	 */
	public static MessageData getInstance(DEREncodable content) {
		ContentInfo info = new ContentInfo(CMSObjectIdentifiers.data, content);
		
		return new MessageData(info);
	}
	
	/**
	 * Returns a BER-encoded byte array representation of this instance.
	 * 
	 * @return a BER-encoded byte array.
	 * @throws IOException if any error occurs.
	 */
	public byte[] getEncoded() throws IOException {
		return contentInfo.getEncoded();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		final StringBuilder builder = new StringBuilder();
		
		builder.append("messageData [\n");
		builder.append("\tcontentType: " + contentInfo.getContentType() + "\n");
		builder.append("\tcontent: " + contentInfo.getContent() + "\n");
		builder.append("]");
		
		return builder.toString();
	}
}
