package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.ScepObjectIdentifiers;
import com.google.code.jscep.transaction.TransactionId;
import com.google.code.jscep.util.LoggingUtil;

public class PkiMessageParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private final PkcsPkiEnvelopeParser parser;
	
	public PkiMessageParser(PkcsPkiEnvelopeParser parser) {
		this.parser = parser;
	}
	
	/**
	 * @param msgBytes DER-encoded degenerate certificates-only signedData
	 * @return a new instance of PkiMessage
	 */
	public PkiMessage parse(byte[] msgBytes) throws IOException {
		LOGGER.entering(getClass().getName(), "parse");

		final ContentInfo sdContentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(msgBytes));
		final SignedData signedData = SignedData.getInstance((ASN1Sequence) sdContentInfo.getContent());
		final Set<SignerInfo> signerInfoSet = getSignerInfo(signedData);

		if (signerInfoSet.size() > 1) {
			IOException ioe = new IOException("Too Many SignerInfos");
			LOGGER.throwing(getClass().getName(), "parse", ioe);
			throw ioe;
		}

		final SignerInfo signerInfo = signerInfoSet.iterator().next();
		final AttributeTable signedAttrs = getAttributeTable(signerInfo);
		final PkiMessageImpl msg = new PkiMessageImpl();
		msg.setTransactionId(extractTransactionId(signedAttrs));
//		msg.setRecipientNonce(extractRecipientNonce(signedAttrs));
		msg.setSenderNonce(extractSenderNonce(signedAttrs));
		msg.setStatus(extractStatus(signedAttrs));
		msg.setMessageType(extractMessageType(signedAttrs));
		
		final ContentInfo edContentInfo = signedData.getEncapContentInfo();
		final DEROctetString octetString = (DEROctetString) edContentInfo.getContent();
		msg.setPkcsPkiEnvelope(parser.parse(octetString.getOctets()));
		
		if (msg.getStatus() == PkiStatus.FAILURE) {
			msg.setFailInfo(extractFailInfo(signedAttrs));
		}
		
		LOGGER.exiting(getClass().getName(), "parse", msg);
		return msg; 
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
	
	private AttributeTable getAttributeTable(SignerInfo signerInfo) {
		return new AttributeTable(signerInfo.getAuthenticatedAttributes());
	}
	
	private TransactionId extractTransactionId(AttributeTable signedAttrs) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.transId);
        Attribute transIdAttr = signedAttrs.get(oid);
        DERPrintableString transId = (DERPrintableString) transIdAttr.getAttrValues().getObjectAt(0);
        
        return new TransactionId(transId.getOctets());
	}

	private FailInfo extractFailInfo(AttributeTable signedAttrs) {
		DERObjectIdentifier oid;
		oid = new DERObjectIdentifier(ScepObjectIdentifiers.failInfo);
		Attribute failInfoAttribute = signedAttrs.get(oid);
		DERPrintableString failInfo = (DERPrintableString) failInfoAttribute.getAttrValues().getObjectAt(0);
		
		return FailInfo.valueOf(Integer.parseInt(failInfo.getString()));
	}

	private Nonce extractRecipientNonce(AttributeTable signedAttrs) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.recipientNonce);
        Attribute recipientNonceAttribute = signedAttrs.get(oid);
        DEROctetString attr = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        return new Nonce(attr.getOctets());
	}
	
	private Nonce extractSenderNonce(AttributeTable signedAttrs) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.senderNonce);
        Attribute recipientNonceAttribute = signedAttrs.get(oid);
        DEROctetString attr = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        return new Nonce(attr.getOctets());
	}

	private PkiStatus extractStatus(AttributeTable signedAttrs) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.pkiStatus);
        Attribute attr = signedAttrs.get(oid);
        DERPrintableString pkiStatus = (DERPrintableString) attr.getAttrValues().getObjectAt(0);

        return PkiStatus.valueOf(Integer.parseInt(pkiStatus.toString()));
	}
	
	private MessageType extractMessageType(AttributeTable signedAttrs) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.messageType);
        Attribute msgTypeAttribute = signedAttrs.get(oid);
        DERPrintableString msgType = (DERPrintableString) msgTypeAttribute.getAttrValues().getObjectAt(0);
        
        return MessageType.valueOf(Integer.parseInt(msgType.getString()));
	}
}
