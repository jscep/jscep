package org.jscep.message;

import static org.jscep.asn1.ScepObjectIdentifier.FAIL_INFO;
import static org.jscep.asn1.ScepObjectIdentifier.MESSAGE_TYPE;
import static org.jscep.asn1.ScepObjectIdentifier.PKI_STATUS;
import static org.jscep.asn1.ScepObjectIdentifier.RECIPIENT_NONCE;
import static org.jscep.asn1.ScepObjectIdentifier.SENDER_NONCE;
import static org.jscep.asn1.ScepObjectIdentifier.TRANS_ID;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

class AttributeTableFactory {
    public AttributeTable fromPkiMessage(PkiMessage<?> message) {
	Hashtable<ASN1ObjectIdentifier, Attribute> table = new Hashtable<ASN1ObjectIdentifier, Attribute>();

	List<Attribute> attributes = getMessageAttributes(message);
	if (message instanceof PkiResponse) {
	    attributes
		    .addAll(getResponseAttributes((PkiResponse<?>) (message)));
	}

	for (Attribute attribute : attributes) {
	    table.put(attribute.getAttrType(), attribute);
	}

	return new AttributeTable(table);
    }

    private List<Attribute> getMessageAttributes(PkiMessage<?> message) {
	List<Attribute> attributes = new ArrayList<Attribute>();

	attributes.add(getAttribute(message.getTransactionId()));
	attributes.add(getAttribute(message.getMessageType()));
	attributes
		.add(getAttribute(message.getSenderNonce(), SENDER_NONCE.id()));

	return attributes;
    }

    private List<Attribute> getResponseAttributes(PkiResponse<?> message) {
	List<Attribute> attributes = new ArrayList<Attribute>();

	attributes.add(getAttribute(message.getPkiStatus()));
	attributes.add(getAttribute(message.getRecipientNonce(),
		RECIPIENT_NONCE.id()));
	if (message.getPkiStatus() == PkiStatus.FAILURE) {
	    attributes.add(getAttribute(message.getFailInfo()));
	}

	return attributes;
    }

    private Attribute getAttribute(FailInfo failInfo) {
	ASN1ObjectIdentifier oid = toOid(FAIL_INFO.id());

	return new Attribute(oid, new DERSet(new DERPrintableString(
		Integer.toString(failInfo.getValue()))));
    }

    private Attribute getAttribute(PkiStatus pkiStatus) {
	ASN1ObjectIdentifier oid = toOid(PKI_STATUS.id());

	return new Attribute(oid, new DERSet(new DERPrintableString(
		Integer.toString(pkiStatus.getValue()))));
    }

    private Attribute getAttribute(Nonce nonce, String id) {
	ASN1ObjectIdentifier oid = toOid(id);

	return new Attribute(oid, new DERSet(new DEROctetString(
		nonce.getBytes())));
    }

    private Attribute getAttribute(MessageType messageType) {
	ASN1ObjectIdentifier oid = toOid(MESSAGE_TYPE.id());
	return new Attribute(oid, new DERSet(new DERPrintableString(
		Integer.toString(messageType.getValue()))));
    }

    private Attribute getAttribute(TransactionId transId) {
	ASN1ObjectIdentifier oid = toOid(TRANS_ID.id());
	return new Attribute(oid, new DERSet(new DERPrintableString(
		transId.toString())));
    }

    private ASN1ObjectIdentifier toOid(String oid) {
	return new ASN1ObjectIdentifier(oid);
    }
}
