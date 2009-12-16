package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.Hex;

import com.google.code.jscep.transaction.CmsException;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.ScepObjectIdentifiers;
import com.google.code.jscep.transaction.TransactionId;
import com.google.code.jscep.util.HexUtil;

public class PkiMessageGenerator {
	private final static Logger LOGGER = Logger.getLogger(PkiMessageGenerator.class.getName());
	
	private MessageType msgType;
	private TransactionId transId;
	private Nonce senderNonce;
	private KeyPair keyPair;
	private X509Certificate identity;
	private String digest;
	
	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	public void setIdentity(X509Certificate identity) {
		this.identity = identity;
	}
	
	public void setDigest(String digest) {
		this.digest = digest;
	}
	
	public void setSenderNonce(Nonce nonce) {
		this.senderNonce = nonce;
	}
	
	public void setMessageType(MessageType msgType) {
		this.msgType = msgType;
	}
	
	public void setTransactionId(TransactionId transId) {
		this.transId = transId;
	}
	
	public PkiMessage generate(PkcsPkiEnvelope envelope) throws GeneralSecurityException, CmsException, IOException {
		// envelope is the data to wrap.
		CMSProcessable envelopedData = new CMSProcessableByteArray(envelope.getEncoded());
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    	
    	final List<X509Certificate> certList = new ArrayList<X509Certificate>(1);
        certList.add(identity);
        
        CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
        try {
			gen.addCertificatesAndCRLs(certs);
		} catch (CMSException e) {
			throw new CmsException(e);
		}
		Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>();
		attributes.put(toAttribute(msgType).getAttrType(), toAttribute(msgType));
        attributes.put(toAttribute(transId).getAttrType(), toAttribute(transId));
        attributes.put(toAttribute(senderNonce).getAttrType(), toAttribute(senderNonce));
		AttributeTable table = new AttributeTable(attributes);
        gen.addSigner(keyPair.getPrivate(), identity, digest, table, null);
        
    	CMSSignedData signedData;
		try {
			signedData = gen.generate(envelopedData, true, "BC");
		} catch (CMSException e) {
			throw new CmsException(e);
		}
    	LOGGER.info("OUTGOING SignedData:\n" + HexUtil.formatHex(Hex.encode(signedData.getEncoded())));
    	
		final PkiMessageImpl msg = new PkiMessageImpl();
		msg.setTransactionId(transId);
		msg.setMessageType(msgType);
		msg.setSenderNonce(senderNonce);
		msg.setPkcsPkiEnvelope(envelope);
		msg.setEncoded(signedData.getEncoded());
		
		return msg;
	}
	
	private Attribute toAttribute(MessageType msgType) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.messageType);
    	DERPrintableString attr = new DERPrintableString(Integer.toString(msgType.getValue()));
    	
        return new Attribute(oid, new DERSet(attr));
	}
	
	private Attribute toAttribute(TransactionId transId) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.transId);
		
        return new Attribute(oid, new DERSet(new DERPrintableString(transId.getBytes())));
	}
	
	 private Attribute toAttribute(Nonce senderNonce) {
    	DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.senderNonce);
    	
        return new Attribute(oid, new DERSet(new DEROctetString(senderNonce.getBytes())));
    }
}
