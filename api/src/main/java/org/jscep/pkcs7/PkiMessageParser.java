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
package org.jscep.pkcs7;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.jscep.asn1.ScepObjectIdentifiers;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.PkiStatus;
import org.jscep.util.LoggingUtil;


/**
 * This class is used for parsing SCEP pkiMessage instances.
 * 
 * @author David Grant
 */
public class PkiMessageParser {
	private static Logger LOGGER = LoggingUtil.getLogger(PkiMessageParser.class);
	private PrivateKey privateKey;
	
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	/**
	 * @param msgBytes DER-encoded degenerate certificates-only signedData
	 * @return a new instance of PkiMessage
	 */
	public PkiMessage parse(ContentInfo contentInfo) throws IOException {
		LOGGER.entering(getClass().getName(), "parse", contentInfo);

		final DERObjectIdentifier contentType = contentInfo.getContentType();
		if (contentType.equals(CMSObjectIdentifiers.signedData) == false) {
			LOGGER.warning("The contentType in pkiMessage MUST be signedData, was: " + contentType);
		}
		final SignedData content = SignedData.getInstance(contentInfo.getContent());
		
		final DERInteger version = content.getVersion();
		
		// 3.1 version MUST be 1
		if (version.getValue().equals(BigInteger.ONE) == false) {
			LOGGER.warning("The version in pkiMessage MUST be one, was: " + contentType);
		}
		
		final Set<SignerInfo> signerInfoSet = getSignerInfo(content);

		if (signerInfoSet.size() != 1) {
			IOException ioe = new IOException("Too Many SignerInfos");
			LOGGER.throwing(getClass().getName(), "parse", ioe);
			throw ioe;
		}
		
		final SignerInfo signerInfo = signerInfoSet.iterator().next();
		final AttributeTable authAttrs = new AttributeTable(signerInfo.getAuthenticatedAttributes());
		
		// §3.1. SCEP pkiMessage
		// 
		// The SignerInfo MUST contain a set of authenticatedAttributes.  All messages
		// must contain:
		//
		// * an SCEP transactionID attribute
		checkAttribute(authAttrs, ScepObjectIdentifiers.transId);
		// * an SCEP messageType attribute
		checkAttribute(authAttrs, ScepObjectIdentifiers.messageType);
		// * an SCEP senderNonce attribute
		checkAttribute(authAttrs, ScepObjectIdentifiers.senderNonce);
		// * any attributes required by PKCS #7 section 9.2
		checkAttribute(authAttrs, PKCSObjectIdentifiers.pkcs_9_at_contentType);
		checkAttribute(authAttrs, PKCSObjectIdentifiers.pkcs_9_at_messageDigest);
		
		if (isResponse(authAttrs)) {
			// If the message is a response, it MUST also include
			//
			// * an SCEP pkiStatus attribute
			checkAttribute(authAttrs, ScepObjectIdentifiers.pkiStatus);
			// * an SCEP recipientNonce attribute
			checkAttribute(authAttrs, ScepObjectIdentifiers.recipientNonce);
		}

		final PkiMessage msg = new PkiMessage(contentInfo);
		if (msg.isRequest() || msg.getPkiStatus() == PkiStatus.SUCCESS) {
			final PkcsPkiEnvelopeParser envelopeParser = new PkcsPkiEnvelopeParser(privateKey);
			final ContentInfo envelopeContentInfo = content.getEncapContentInfo();
			// §3.1. SCEP pkiMessage
			// ... the contentType in contentInfo MUST be data
			final DERObjectIdentifier encapsulatedContentType = envelopeContentInfo.getContentType();
			if (encapsulatedContentType.equals(CMSObjectIdentifiers.data) == false) {
				LOGGER.severe("The contentType in contentInfo MUST be data, was: " + encapsulatedContentType);
			}
			final ASN1OctetString octetString = (ASN1OctetString) envelopeContentInfo.getContent();
			final byte[] octets = octetString.getOctets();
			final PkcsPkiEnvelope pkcsPkiEnvelope = envelopeParser.parse(ContentInfo.getInstance(ASN1Object.fromByteArray(octets)));
			msg.setPkcsPkiEnvelope(pkcsPkiEnvelope);	
		} else {
			// TODO: Assert No ContentInfo
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-3
		}
		
		LOGGER.exiting(getClass().getName(), "parse", msg);
		return msg; 
	}
	
	private void checkAttribute(AttributeTable table, DERObjectIdentifier oid) throws IOException {
		if (table.get(oid) == null) {
			throw new IOException("pkiMessage is missing mandatory attribute: " + oid.getId());
		}
	}
	
	private boolean isResponse(AttributeTable table) {
		final ASN1Set messageTypeSet = table.get(ScepObjectIdentifiers.messageType).getAttrValues();
		if (messageTypeSet.size() != 1) {
			return false;
		}
		final DERPrintableString msgType = (DERPrintableString) messageTypeSet.getObjectAt(0);
		
		return MessageType.valueOf(Integer.valueOf(msgType.getString())) == MessageType.CertRep;
	}
	
	private Set<SignerInfo> getSignerInfo(SignedData signedData) {
		final Set<SignerInfo> set = new HashSet<SignerInfo>();
		
		for (int i = 0; i < signedData.getSignerInfos().size(); i++) {
			set.add(SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(i)));
		}
		
		return set;
	}
}
