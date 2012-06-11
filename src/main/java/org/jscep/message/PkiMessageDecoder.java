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

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.asn1.ScepObjectIdentifiers;
import org.jscep.transaction.*;
import org.jscep.util.LoggingUtil;
import org.slf4j.Logger;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;

public class PkiMessageDecoder {
    private static Logger LOGGER = LoggingUtil.getLogger(PkiMessageDecoder.class);
	private final PkcsPkiEnvelopeDecoder decoder;
	
	public PkiMessageDecoder(PkcsPkiEnvelopeDecoder decoder) {
		this.decoder = decoder;
	}
	
	@SuppressWarnings("unchecked")
	public PkiMessage<? extends ASN1Encodable> decode(CMSSignedData signedData) throws IOException {
        LOGGER.debug("Decoding message: {}", signedData.getEncoded());
		// The signed content is always an octet string
		CMSProcessable signedContent = signedData.getSignedContent();
		
		CertStore certs;
		try {
			certs = signedData.getCertificatesAndCRLs("Collection", (String) null);
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
			X509Certificate cert = (X509Certificate) certColl.iterator().next();
            LOGGER.debug("Verifying message using key belonging to '{}'", cert.getSubjectDN());
			try {
				signerInfo.verify(cert.getPublicKey(), (String) null);
			} catch (Exception e) {
				throw new IOException(e);
			}
		} else {
            LOGGER.error("Unable to verify message");
        }
		
		Hashtable<DERObjectIdentifier, Attribute> attrTable = signerInfo.getSignedAttributes().toHashtable();
		
		MessageType messageType = toMessageType(attrTable.get(ScepObjectIdentifiers.messageType));
		Nonce senderNonce = toNonce(attrTable.get(ScepObjectIdentifiers.senderNonce));
		TransactionId transId = toTransactionId(attrTable.get(ScepObjectIdentifiers.transId));

        PkiMessage<? extends ASN1Encodable> decoded;
		if (messageType == MessageType.CERT_REP) {
			PkiStatus pkiStatus = toPkiStatus(attrTable.get(ScepObjectIdentifiers.pkiStatus));
			Nonce recipientNonce = toNonce(attrTable.get(ScepObjectIdentifiers.recipientNonce));

			if (pkiStatus == PkiStatus.FAILURE) {
				FailInfo failInfo = toFailInfo(attrTable.get(ScepObjectIdentifiers.failInfo));
				
				decoded = new CertRep(transId, senderNonce, recipientNonce, failInfo);
			} else  if (pkiStatus == PkiStatus.PENDING) {
				
				decoded = new CertRep(transId, senderNonce, recipientNonce);
			} else {
				final EnvelopedData ed = getEnvelopedData((byte[]) signedContent.getContent());
				final ASN1Encodable envelopedContent = decoder.decode(ed);
				DEROctetString messageData = new DEROctetString(envelopedContent);
				
				decoded = new CertRep(transId, senderNonce, recipientNonce, messageData);
			}
		} else if (messageType == MessageType.GET_CERT) {
			EnvelopedData ed = getEnvelopedData((byte[]) signedContent.getContent());
			IssuerAndSerialNumber messageData = IssuerAndSerialNumber.getInstance(decoder.decode(ed));
			
			decoded = new GetCert(transId, senderNonce, messageData);
		} else  if (messageType == MessageType.GET_CERT_INITIAL) {
			EnvelopedData ed = getEnvelopedData((byte[]) signedContent.getContent());
			
			IssuerAndSubject messageData = IssuerAndSubject.getInstance(decoder.decode(ed));
			
			decoded = new GetCertInitial(transId, senderNonce, messageData);
		} else if (messageType == MessageType.GET_CRL) {
			EnvelopedData ed = getEnvelopedData((byte[]) signedContent.getContent());
			IssuerAndSerialNumber messageData = IssuerAndSerialNumber.getInstance(decoder.decode(ed));
			
			decoded = new GetCRL(transId, senderNonce, messageData);
		} else {
			EnvelopedData ed = getEnvelopedData((byte[]) signedContent.getContent());
			CertificationRequest messageData = CertificationRequest.getInstance(decoder.decode(ed));
			
			decoded = new PKCSReq(transId, senderNonce, messageData);
		}

        LOGGER.debug("Decoded to: {}", decoded);
        return decoded;
	}
	
	private EnvelopedData getEnvelopedData(byte[] bytes) throws IOException {
		// We expect the byte array to be a sequence
		ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(bytes);
		// ... and that sequence to be a ContentInfo (but might be the EnvelopedData)
		ContentInfo contentInfo = new ContentInfo(seq);
		// If it *is* a ContentInfo, the content *should* be EnvelopedData
		DEREncodable content = contentInfo.getContent();
		
		return EnvelopedData.getInstance(content);
	}
	
	private Nonce toNonce(Attribute attr) {
		// Sometimes we don't get a sender nonce.
		if (attr == null) {
			return null;
		}
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
