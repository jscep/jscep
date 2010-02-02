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
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.util.LoggingUtil;

/**
 * This class is used for parsing SCEP pkiMessage instances.
 * 
 * @author David Grant
 */
public class PkiMessageParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private PrivateKey privateKey;
	
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	/**
	 * @param msgBytes DER-encoded degenerate certificates-only signedData
	 * @return a new instance of PkiMessage
	 */
	public PkiMessage parse(byte[] msgBytes) throws IOException {
		LOGGER.entering(getClass().getName(), "parse", msgBytes);

		final ContentInfo sdContentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(msgBytes));
		final SignedData signedData = SignedData.getInstance((ASN1Sequence) sdContentInfo.getContent());
		
		// 3.1 version MUST be 1
		assert(signedData.getVersion().getValue().equals(BigInteger.ONE));
		
		final Set<SignerInfo> signerInfoSet = getSignerInfo(signedData);

		if (signerInfoSet.size() > 1) {
			IOException ioe = new IOException("Too Many SignerInfos");
			LOGGER.throwing(getClass().getName(), "parse", ioe);
			throw ioe;
		}

		final PkiMessage msg = new PkiMessage(sdContentInfo);
		if (msg.isRequest() || msg.getPkiStatus() == PkiStatus.SUCCESS) {
			final PkcsPkiEnvelopeParser envelopeParser = new PkcsPkiEnvelopeParser(privateKey);
			final ContentInfo envelopeContentInfo = signedData.getEncapContentInfo();
			// 3.1 the contentType in contentInfo MUST be data
			DERObjectIdentifier contentType = envelopeContentInfo.getContentType();
			if (contentType.equals(CMSObjectIdentifiers.data) == false) {
				LOGGER.severe("The contentType in contentInfo MUST be data, was: " + contentType);
			}
			msg.setPkcsPkiEnvelope(envelopeParser.parse(getEnvelopedData(envelopeContentInfo.getContent())));	
		} else {
			// TODO: Assert No ContentInfo
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-3
		}
		
		LOGGER.exiting(getClass().getName(), "parse", msg);
		return msg; 
	}
	
	private EnvelopedData getEnvelopedData(DEREncodable content) throws IOException {
		// According to PKCS #9, data consists of an octet string.
		final ASN1OctetString octetString = (ASN1OctetString) content;
		final byte[] octets = octetString.getOctets();
		final ContentInfo contentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(octets));
		final DERObjectIdentifier contentType = contentInfo.getContentType();
		
		if (contentType.equals(CMSObjectIdentifiers.envelopedData) == false) {
			LOGGER.warning("Expected envelopedData ContentInfo, was " + contentType);
		}
		
		return new EnvelopedData((ASN1Sequence) contentInfo.getContent());
	}
	
	private Set<SignerInfo> getSignerInfo(SignedData signedData) {
		final Set<SignerInfo> set = new HashSet<SignerInfo>();
		final Enumeration<?> signerInfos = signedData.getSignerInfos().getObjects();
		
		while (signerInfos.hasMoreElements()) {
			final ASN1Sequence seq = (ASN1Sequence) signerInfos.nextElement();
			set.add(new SignerInfo(seq));
		}
		
		return set;
	}
}
