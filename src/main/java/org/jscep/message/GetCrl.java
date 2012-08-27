package org.jscep.message;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

/**
 * This class represents a <tt>GetCRL</tt> <tt>pkiMessage</tt>, which wraps an
 * <tt>IssuerAndSerialNumber</tt> object.
 */
public class GetCrl extends PkiRequest<IssuerAndSerialNumber> {
    /**
     * Creates a new <tt>GetCrl</tt> instance.
     * 
     * @param transId the transaction ID for this request.
     * @param senderNonce the nonce for this request.
     * @param messageData the <tt>IssuerAndSerialNumber</tt> of the certificate referenced by the CRL.
     */
    public GetCrl(TransactionId transId, Nonce senderNonce,
	    IssuerAndSerialNumber messageData) {
	super(transId, MessageType.GET_CRL, senderNonce, messageData);
    }
}
