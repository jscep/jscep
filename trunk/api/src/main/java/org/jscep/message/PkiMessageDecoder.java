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

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.asn1.ScepObjectIdentifiers;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

public class PkiMessageDecoder {
	private final PkcsPkiEnvelopeDecoder decoder;
	
	public PkiMessageDecoder(PkcsPkiEnvelopeDecoder decoder) {
		this.decoder = decoder;
	}
	
	@SuppressWarnings("unchecked")
	public PkiMessage<? extends ASN1Encodable> decode(CMSSignedData signedData) throws IOException {
		String contentType = signedData.getSignedContentTypeOID();
		if (PKCSObjectIdentifiers.data.toString().equals(contentType)) {
			// OK
		}
		// The signed content is always an octet string
		CMSProcessable signedContent = signedData.getSignedContent();
		
		CertStore certs;
		try {
			certs = signedData.getCertificatesAndCRLs("Collection", null);
		} catch (Exception e) {
			throw new IOException(e);
		}
		Collection<SignerInformation> signerInfos = signedData.getSignerInfos().getSigners();
		SignerInformation signerInfo = signerInfos.iterator().next();
		Collection<? extends Certificate> certColl;
		try {
			certColl = certs.getCertificates(signerInfo.getSID());
		} catch (Exception e) {
			throw new IOException(e);
		}
		if (certColl.size() > 0) {
			Certificate cert = certColl.iterator().next();
			try {
				signerInfo.verify(cert.getPublicKey(), null);
			} catch (Exception e) {
				throw new IOException(e);
			}
		}
		
		Hashtable<DERObjectIdentifier, Attribute> attrTable = signerInfo.getSignedAttributes().toHashtable();
		
		MessageType messageType = toMessageType(attrTable.get(ScepObjectIdentifiers.messageType));
		Nonce senderNonce = toNonce(attrTable.get(ScepObjectIdentifiers.senderNonce));
		TransactionId transId = toTransactionId(attrTable.get(ScepObjectIdentifiers.transId));
		
		if (messageType == MessageType.CertRep) {
			PkiStatus pkiStatus = toPkiStatus(attrTable.get(ScepObjectIdentifiers.pkiStatus));
			Nonce recipientNonce = toNonce(attrTable.get(ScepObjectIdentifiers.recipientNonce));

			if (pkiStatus == PkiStatus.FAILURE) {
				FailInfo failInfo = toFailInfo(attrTable.get(ScepObjectIdentifiers.failInfo));
				
				return new CertRep(transId, senderNonce, recipientNonce, pkiStatus, failInfo);
			} else  if (pkiStatus == PkiStatus.PENDING) {
				
				return new CertRep(transId, senderNonce, recipientNonce, pkiStatus);
			} else {
				byte[] bytes = (byte[]) signedContent.getContent();
				CMSEnvelopedData envelopedData;
				try {
					envelopedData = new CMSEnvelopedData(bytes);
				} catch (CMSException e) {
					throw new IOException(e);
				}
				// Perhaps we need to wrap this
				ContentInfo contentInfo = ContentInfo.getInstance(decoder.decode(envelopedData));
				SignedData messageData = new SignedData((ASN1Sequence) contentInfo.getContent());
				
				return new CertRep(transId, senderNonce, recipientNonce, pkiStatus, messageData);
			}
		} else if (messageType == MessageType.GetCert) {
			byte[] bytes = (byte[]) signedContent.getContent();
			CMSEnvelopedData envelopedData;
			try {
				envelopedData = new CMSEnvelopedData(bytes);
			} catch (CMSException e) {
				throw new IOException(e);
			}
			IssuerAndSerialNumber messageData = IssuerAndSerialNumber.getInstance(decoder.decode(envelopedData));
			
			return new GetCert(transId, senderNonce, messageData);
		} else  if (messageType == MessageType.GetCertInitial) {
			byte[] bytes = (byte[]) signedContent.getContent();
			CMSEnvelopedData envelopedData;
			try {
				envelopedData = new CMSEnvelopedData(bytes);
			} catch (CMSException e) {
				throw new IOException(e);
			}
			IssuerAndSubject messageData = IssuerAndSubject.getInstance(decoder.decode(envelopedData));
			
			return new GetCertInitial(transId, senderNonce, messageData);
		} else if (messageType == MessageType.GetCRL) {
			byte[] bytes = (byte[]) signedContent.getContent();
			CMSEnvelopedData envelopedData;
			try {
				envelopedData = new CMSEnvelopedData(bytes);
			} catch (CMSException e) {
				throw new IOException(e);
			}
			IssuerAndSerialNumber messageData = IssuerAndSerialNumber.getInstance(decoder.decode(envelopedData));
			
			return new GetCRL(transId, senderNonce, messageData);
		} else {
			byte[] bytes = (byte[]) signedContent.getContent();
			CMSEnvelopedData envelopedData;
			try {
				envelopedData = new CMSEnvelopedData(bytes);
			} catch (CMSException e) {
				throw new IOException(e);
			}
			CertificationRequest messageData = CertificationRequest.getInstance(decoder.decode(envelopedData));
			
			return new PKCSReq(transId, senderNonce, messageData);
		}
	}
	
	private Nonce toNonce(Attribute attr) {
		final DEROctetString octets = (DEROctetString) attr.getAttrValues().getObjectAt(0);
		
		return new Nonce(octets.getOctets());
	}
	
	private MessageType toMessageType(Attribute attr) {
		final DERPrintableString string = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return MessageType.valueOf(Integer.valueOf(string.getString()));
	}
	
	private TransactionId toTransactionId(Attribute attr) {
		final DERPrintableString string = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return new TransactionId(string.getOctets());
	}
	
	private PkiStatus toPkiStatus(Attribute attr) {
		final DERPrintableString string = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return PkiStatus.valueOf(Integer.valueOf(string.getString()));
	}
	
	private FailInfo toFailInfo(Attribute attr) {
		final DERPrintableString string = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return FailInfo.valueOf(Integer.valueOf(string.getString()));
	}
}
