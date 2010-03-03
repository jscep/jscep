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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;
import org.jscep.asn1.SCEPObjectIdentifiers;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;
import org.jscep.util.AlgorithmDictionary;
import org.jscep.util.LoggingUtil;


/**
 * This class is used to generate a new instance of {@link PkiMessage}.
 * <p>
 * Callers should use the mutator methods to configure particular options, depending
 * on the destination of the message.
 * <p>
 * Example usage:
 * <pre>
 * X509Certificate recipient = ...;
 * KeyPair pair = ...;
 * 
 * PkiMessageGenerator gen = new PkiMessageGenerator();
 * gen.setMessageType(MessageType.GetCert);
 * gen.setTransactionId(TransactionId.createTransactionId(keyPair, "SHA-1"));
 * gen.setSenderNonce(Nonce.nextNonce());
 * gen.setRecipient(recipient);
 * gen.setKeyPair(pair);
 * gen.setMessageDigest(...);
 * gen.setCipherAlgorithm(...);
 * 
 * PkiMessage message = gen.generate();
 * </pre>
 * 
 * @author David Grant
 */
public class PkiMessageGenerator implements Cloneable {
	private static Logger LOGGER = LoggingUtil.getLogger(PkiMessageGenerator.class);
	
	private MessageType msgType;
	private TransactionId transId;
	private Nonce senderNonce;
	private Nonce recipientNonce;
	private FailInfo failInfo;
	private KeyPair keyPair;
	private X509Certificate identity;
	private String digestAlgorithm;
	private PkiStatus pkiStatus;
	private ContentInfo content;
	private byte[] hash;
	private X509Certificate recipient;
	private String cipherAlgorithm;
	private MessageData msgData;
	
	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	public void setSigner(X509Certificate identity) {
		this.identity = identity;
	}
	
	public void setFailInfo(FailInfo failInfo) {
		this.failInfo = failInfo;
	}
	
	public void setRecipientNonce(Nonce nonce) {
		this.recipientNonce = nonce;
	}
	
	public void setMessageDigest(String digest) {
		this.digestAlgorithm = digest;
	}
	
	public Nonce getSenderNonce() {
		return senderNonce;
	}
	
	public void setSenderNonce(Nonce nonce) {
		this.senderNonce = nonce;
	}
	
	public void setPkiStatus(PkiStatus pkiStatus) {
		this.pkiStatus = pkiStatus;
	}
	
	public void setMessageData(MessageData msgData) {
		this.msgData = msgData;
	}
	
	public void setMessageType(MessageType msgType) {
		this.msgType = msgType;
	}
	
	public void setTransactionId(TransactionId transId) {
		this.transId = transId;
	}
	
	public void setRecipient(X509Certificate recipient) {
		this.recipient = recipient;
	}
	
	public void setCipherAlgorithm(String cipherAlgorithm) {
		this.cipherAlgorithm = cipherAlgorithm;
	}
	
	/**
	 * Generates a new {@link PkiMessage} according to the options specified by the 
	 * caller.
	 * 
	 * @return a new instance of {@link PkiMessage}
	 * @throws IOException if any I/O error occurs.
	 * @throws IllegalStateException if this class has been incorrectly configured.
	 */
	public PkiMessage generate() throws IOException, IllegalStateException {
		LOGGER.entering(getClass().getName(), "generate");
		
		// 3.1
		if (transId == null) {
			throw new IllegalStateException("Missing transactionID");
		}
		if (msgType == null) {
			throw new IllegalStateException("Missing messageType");
		}
		if (senderNonce == null) {
			throw new IllegalStateException("Missing senderNonce");
		}
		if (msgType == MessageType.CertRep) {
			// Response
			if (pkiStatus == null) {
				throw new IllegalStateException("Missing pkiStatus");
			} else if (pkiStatus == PkiStatus.FAILURE) {
				if (failInfo == null) {
					throw new IllegalStateException("Missing failInfo");
				}
			}
			if (recipientNonce == null) {
				throw new IllegalStateException("Missing recipientNonce");
			}
		}
		
		if (digestAlgorithm == null) {
			throw new IllegalStateException("Missing Message Digest Algorithm");
		}
		if (cipherAlgorithm == null) {
			throw new IllegalStateException("Missing Cipher Algorithm");
		}
		if (keyPair == null) {
			throw new IllegalStateException("Missing Key Pair");
		}
		if (recipient == null) {
			throw new IllegalStateException("Missing Recipient");
		}

		final PkcsPkiEnvelope envelope;
		if (msgData == null) {
			envelope = null;
		} else {
			final PkcsPkiEnvelopeGenerator envelopeGenerator = new PkcsPkiEnvelopeGenerator();
			envelopeGenerator.setCipherAlgorithm(cipherAlgorithm);
			envelopeGenerator.setRecipient(recipient);
			envelopeGenerator.setMessageData(msgData);
			envelopeGenerator.setKeyAlgorithm(cipherAlgorithm);
			
			envelope = envelopeGenerator.generate();
			this.content = new ContentInfo((ASN1Sequence) ASN1Object.fromByteArray(envelope.getEncoded()));
		}
		
		final SignedData signedData;
		try {
			final ASN1Set digestAlgorithms = getDigestAlgorithms();
			final ContentInfo contentInfo = getContentInfo();
			final ASN1Set certificates = getCertificates();
			final ASN1Set crls = getCRLs();
			final ASN1Set signerInfos = getSignerInfos();
			signedData = new SignedData(digestAlgorithms, contentInfo, certificates, crls, signerInfos);
			
			// 3.1 version MUST be 1
			assert(signedData.getVersion().getValue().equals(BigInteger.ONE));
			// 3.1 the contentType in contentInfo MUST be data
			assert(signedData.getEncapContentInfo().getContentType().equals(CMSObjectIdentifiers.data));
		} catch (GeneralSecurityException e) {
			RuntimeException rt = new RuntimeException(e);
			LOGGER.throwing(getClass().getName(), "parse", rt);
			throw rt;
		}
		
		final ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
		final PkiMessage msg = new PkiMessage(contentInfo);
		msg.setPkcsPkiEnvelope(envelope);
		
		LOGGER.exiting(getClass().getName(), "generate", msg);
		return msg;
	}
	
	private ContentInfo getContentInfo() {
		DERObjectIdentifier contentType = CMSObjectIdentifiers.data;
		DEREncodable content = getContent();
		
		return new ContentInfo(contentType, content);
	}
	
	private Attribute getContentType() {
		return new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data));
	}
	
	private DEREncodable getContent() {
		if (content == null) {
			return new DERNull();
		}
		return new BERConstructedOctetString(content);
	}
	
	private ASN1Set getCertificates() {
		return new DERSet(getCertificate());
	}
	
	private X509CertificateStructure getCertificate() {
		try {
			ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(identity.getEncoded());
			X509CertificateStructure x509 = new X509CertificateStructure(seq);
			
			return x509;
		} catch (CertificateEncodingException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	private ASN1Set getCRLs() {
		return null;
	}
	
	private ASN1Set getSignerInfos() throws IOException, GeneralSecurityException {
		return new DERSet(getSignerInfo());
	}
	
	private SignerInfo getSignerInfo() throws IOException, GeneralSecurityException {
		final MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
		// TODO: Hardcoded Algorithm
		final Signature sig = Signature.getInstance(AlgorithmDictionary.getRSASignatureAlgorithm(digestAlgorithm));
		
		digest.update(content.getEncoded());
		hash = digest.digest();
		
		final Hashtable<DERObjectIdentifier, Attribute> table = new Hashtable<DERObjectIdentifier, Attribute>();
		table.put(getTransactionId().getAttrType(), getTransactionId());
		table.put(getMessageType().getAttrType(), getMessageType());
		table.put(getSenderNonceAttribute().getAttrType(), getSenderNonceAttribute());
		table.put(getContentType().getAttrType(), getContentType());
		table.put(getSigningTime().getAttrType(), getSigningTime());
		table.put(getMessageDigest().getAttrType(), getMessageDigest());
		
		if (pkiStatus != null) {
			table.put(getStatus().getAttrType(), getStatus());
		}
		if (failInfo != null) {
			table.put(getFailInfo().getAttrType(), getFailInfo());
		}
		if (recipientNonce != null) {
			table.put(getRecipientNonce().getAttrType(), getRecipientNonce());
		}
		
		final AttributeTable signed = new AttributeTable(table);
		final ASN1Set signedAttr = new DERSet(signed.toASN1EncodableVector());
		final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		final DEROutputStream dOut = new DEROutputStream(bOut);
		dOut.writeObject(signedAttr);

		sig.initSign(keyPair.getPrivate());
		sig.update(bOut.toByteArray());
		
		final SignerIdentifier sid = getSignerIdentifier();
		final AlgorithmIdentifier digAlgorithm = getDigestAlgorithm();
		final AlgorithmIdentifier digEncryptionAlgorithm = getDigestEncryptionAlgorithm();
		final ASN1OctetString encryptedDigest = new DEROctetString(sig.sign());
		final ASN1Set unauthenticatedAttributes = getUnauthenticatedAttributes();
		
		return new SignerInfo(sid, digAlgorithm, signedAttr, digEncryptionAlgorithm, encryptedDigest, unauthenticatedAttributes);
	}
	
	private ASN1Set getUnauthenticatedAttributes() {
		return null;
	}
	
	private Attribute getMessageType() {
		final DERObjectIdentifier attrType = SCEPObjectIdentifiers.messageType;
    	final ASN1Set attr = new DERSet(new DERPrintableString(Integer.toString(msgType.getValue())));
    	
        return new Attribute(attrType, attr);
	}
		
	private Attribute getMessageDigest() {
		return new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hash)));
	}
	
	private Attribute getSigningTime() {
		return new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date())));
	}
	
	private Attribute getSenderNonceAttribute() {
		final DERObjectIdentifier attrType = SCEPObjectIdentifiers.senderNonce;
    	final ASN1Set attr = new DERSet(new DEROctetString(senderNonce.getBytes()));
    	
        return new Attribute(attrType, attr);
	}
	
	private Attribute getTransactionId() {
		final DERObjectIdentifier attrType = SCEPObjectIdentifiers.transId;
		final ASN1Set attrValues = new DERSet(new DERPrintableString(transId.getBytes()));
		
		return new Attribute(attrType, attrValues);
	}
	
	private ASN1Set getDigestAlgorithms() {
		return new DERSet(getDigestAlgorithm());
	}
	
	private AlgorithmIdentifier getDigestAlgorithm() {
		return AlgorithmDictionary.getAlgId(digestAlgorithm);
	}
	
	private AlgorithmIdentifier getDigestEncryptionAlgorithm() {
		return new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
	}
	
	private SignerIdentifier getSignerIdentifier() {
		return new SignerIdentifier(getIssuerAndSerialNumber());
	}
	
	private IssuerAndSerialNumber getIssuerAndSerialNumber() {
		return new IssuerAndSerialNumber(getIssuer(), getSerialNumber());
	}
	
	private X509Name getIssuer() {
		return new X509Name(identity.getIssuerDN().getName());
	}
	
	private BigInteger getSerialNumber() {
		return identity.getSerialNumber();
	}
	
	private Attribute getFailInfo() {
		DERPrintableString attr = new DERPrintableString(Integer.toString(failInfo.getValue()));

		return new Attribute(SCEPObjectIdentifiers.failInfo, new DERSet(attr));
	}
	
	private Attribute getStatus() {
		DERPrintableString attr = new DERPrintableString(Integer.toString(pkiStatus.getValue()));

		return new Attribute(SCEPObjectIdentifiers.pkiStatus, new DERSet(attr));
	}
	
	private Attribute getRecipientNonce() {
		return new Attribute(SCEPObjectIdentifiers.recipientNonce, new DERSet(new DEROctetString(recipientNonce.getBytes())));
	}

	@Override
	public PkiMessageGenerator clone() {
		try {
			return (PkiMessageGenerator) super.clone();
		} catch (CloneNotSupportedException e) {
			throw new RuntimeException(e);
		}
	}
}
