package com.google.code.jscep.pkcs7;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DEREncodable;
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
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;

import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.ScepObjectIdentifiers;
import com.google.code.jscep.transaction.TransactionId;
import com.google.code.jscep.util.LoggingUtil;

public class PkiMessageGenerator {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	
	private MessageType msgType;
	private TransactionId transId;
	private Nonce senderNonce;
	private Nonce recipientNonce;
	private FailInfo failInfo;
	private KeyPair keyPair;
	private X509Certificate identity;
	private AlgorithmIdentifier digest;
	private PkiStatus status;
	private ContentInfo content;
	
	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	public void setIdentity(X509Certificate identity) {
		this.identity = identity;
	}
	
	public void setFailInfo(FailInfo failInfo) {
		this.failInfo = failInfo;
	}
	
	public void setRecipientNonce(Nonce nonce) {
		this.recipientNonce = nonce;
	}
	
	public void setDigest(AlgorithmIdentifier digest) {
		this.digest = digest;
	}
	
	public void setSenderNonce(Nonce nonce) {
		this.senderNonce = nonce;
	}
	
	public void setStatus(PkiStatus status) {
		this.status = status;
	}
	
	public void setMessageType(MessageType msgType) {
		this.msgType = msgType;
	}
	
	public void setTransactionId(TransactionId transId) {
		this.transId = transId;
	}
	
	public PkiMessage generate(PkcsPkiEnvelope envelope) throws IOException {
		this.content = new ContentInfo((ASN1Sequence) ASN1Object.fromByteArray(envelope.getEncoded()));
		
		LOGGER.entering(getClass().getName(), "generate");
		
        ContentInfo ci;
		try {
			final ASN1Set digestAlgorithms = getDigestAlgorithms();
			final ContentInfo contentInfo = getContentInfo();
			final ASN1Set certificates = getCertificates();
			final ASN1Set crls = getCRLs();
			final ASN1Set signerInfos = getSignerInfos();
			final SignedData sd = new SignedData(digestAlgorithms, contentInfo, certificates, crls, signerInfos);
			
			DERObjectIdentifier contentType = CMSObjectIdentifiers.signedData;
			ci = new ContentInfo(contentType, sd);
		} catch (GeneralSecurityException e) {
			RuntimeException rt = new RuntimeException(e);
			LOGGER.throwing(getClass().getName(), "parse", rt);
			throw rt;
		}
    	
		final PkiMessageImpl msg = new PkiMessageImpl();
		msg.setMessageType(msgType);
		msg.setStatus(status); // Reply
		msg.setFailInfo(failInfo); // Reply
		msg.setSenderNonce(senderNonce);
		msg.setRecipientNonce(recipientNonce); // Reply
		msg.setTransactionId(transId);
		
		msg.setPkcsPkiEnvelope(envelope);
		msg.setEncoded(ci.getEncoded());
		
		LOGGER.exiting(getClass().getName(), "generate", msg);
		return msg;
	}
	
	private ContentInfo getContentInfo() {
		DERObjectIdentifier contentType = getContentType();
		DEREncodable content = getContent();
		
		return new ContentInfo(contentType, content);
	}
	
	private DERObjectIdentifier getContentType() {
		return CMSObjectIdentifiers.data;
	}
	
	private DEREncodable getContent() {
		ASN1OctetString str = new BERConstructedOctetString(content);
		return str;
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
		final MessageDigest digest = MessageDigest.getInstance("SHA1");
		final Signature sig = Signature.getInstance("SHA1withRSA");
		
		digest.update(content.getEncoded());
		byte[] hash = digest.digest();
		
		Hashtable table = new Hashtable();
		table.put(getTransactionId().getAttrType(), getTransactionId());
		table.put(getMessageType().getAttrType(), getMessageType());
//		table.put(getS, arg1)
		Attribute contentAttr = new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data));
		table.put(contentAttr.getAttrType(), contentAttr);
		Attribute signingTime = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date())));
		table.put(signingTime.getAttrType(), signingTime);
		Attribute hashAttr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hash)));
		table.put(hashAttr.getAttrType(), hashAttr);
		
		AttributeTable signed = new AttributeTable(table);
		ASN1Set signedAttr = new DERSet(signed.toASN1EncodableVector());
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		DEROutputStream dOut = new DEROutputStream(bOut);
		dOut.writeObject(signedAttr);

		sig.initSign(keyPair.getPrivate());
		sig.update(bOut.toByteArray());
		
		SignerIdentifier sid = getSignerIdentifier();
		AlgorithmIdentifier digAlgorithm = getDigestAlgorithm();
		AlgorithmIdentifier digEncryptionAlgorithm = getDigestEncryptionAlgorithm();
		ASN1OctetString encryptedDigest = new DEROctetString(sig.sign());
		ASN1Set unauthenticatedAttributes = getUnauthenticatedAttributes();
		
		return new SignerInfo(sid, digAlgorithm, signedAttr, digEncryptionAlgorithm, encryptedDigest, unauthenticatedAttributes);
	}
	
	private ASN1Set getUnauthenticatedAttributes() {
		return null;
	}
	
	private ASN1OctetString getEncryptedDigest() throws IOException {
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA1");
			final Signature sig = Signature.getInstance("SHA1withRSA");
			
			digest.update(content.getEncoded());
			byte[] hash = digest.digest();
			
			Hashtable table = new Hashtable();
			table.put(getTransactionId().getAttrType(), getTransactionId());
			table.put(getMessageType().getAttrType(), getMessageType());
			table.put(getSenderNonce().getAttrType(), getSenderNonce());
			Attribute contentAttr = new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data));
			table.put(contentAttr.getAttrType(), contentAttr);
			Attribute signingTime = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date())));
			table.put(signingTime.getAttrType(), signingTime);
			Attribute hashAttr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hash)));
			
			AttributeTable signed = new AttributeTable(table);
			ASN1Set signedAttr = new DERSet(signed.toASN1EncodableVector());
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);
			dOut.writeObject(signedAttr);

			sig.initSign(keyPair.getPrivate());
			sig.update(bOut.toByteArray());
			
			return new DEROctetString(sig.sign());
			
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
//		} catch (IOException e) {
//			throw new RuntimeException(e);
		}
	}
	
	private ASN1Set getAuthenticatedAttributes() {
		final ASN1EncodableVector vector = new ASN1EncodableVector();
		
		vector.add(getTransactionId());
		vector.add(getMessageType());
		
		return new DERSet(vector);
	}
	
	private Attribute getMessageType() {
		final DERObjectIdentifier attrType = new DERObjectIdentifier(ScepObjectIdentifiers.messageType);
    	final ASN1Set attr = new DERSet(new DERPrintableString(Integer.toString(msgType.getValue())));
    	
        return new Attribute(attrType, attr);
	}
	
	private Attribute getSenderNonce() {
		final DERObjectIdentifier attrType = new DERObjectIdentifier(ScepObjectIdentifiers.senderNonce);
    	final ASN1Set attr = new DERSet(new DERPrintableString(senderNonce.getBytes()));
    	
        return new Attribute(attrType, attr);
	}
	
	private Attribute getTransactionId() {
		final DERObjectIdentifier attrType = new DERObjectIdentifier(ScepObjectIdentifiers.transId);
		final ASN1Set attrValues = new DERSet(new DERPrintableString(transId.getBytes()));
		
		return new Attribute(attrType, attrValues);
	}
	
	private ASN1Set getDigestAlgorithms() {
		return new DERSet(getDigestAlgorithm());
	}
	
	private AlgorithmIdentifier getDigestAlgorithm() {
		return digest;
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
	
	private Attribute toAttribute(MessageType msgType) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.messageType);
    	DERPrintableString attr = new DERPrintableString(Integer.toString(msgType.getValue()));
    	
        return new Attribute(oid, new DERSet(attr));
	}
	
	private Attribute toAttribute(FailInfo failInfo) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.failInfo);
    	DERPrintableString attr = new DERPrintableString(Integer.toString(failInfo.getValue()));
    	
        return new Attribute(oid, new DERSet(attr));
	}
	
	private Attribute toAttribute(PkiStatus status) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.pkiStatus);
    	DERPrintableString attr = new DERPrintableString(Integer.toString(status.getValue()));
    	
        return new Attribute(oid, new DERSet(attr));
	}
	
	private Attribute toAttribute(TransactionId transId) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.transId);
		
        return new Attribute(oid, new DERSet(new DERPrintableString(transId.getBytes())));
	}
	
	 private Attribute toAttribute(String nonceOid, Nonce senderNonce) {
    	DERObjectIdentifier oid = new DERObjectIdentifier(nonceOid);
    	
        return new Attribute(oid, new DERSet(new DEROctetString(senderNonce.getBytes())));
    }
}
