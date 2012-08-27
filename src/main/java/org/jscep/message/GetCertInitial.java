package org.jscep.message;

import org.jscep.asn1.IssuerAndSubject;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

/**
 * This class represents a <tt>GetCertInitial</tt> <tt>pkiMessage</tt>, which
 * wraps an <tt>IssuerAndSubject</tt> object.
 */
public class GetCertInitial extends PkiRequest<IssuerAndSubject> {
    /**
     * Creates a new <tt>GetCertInitial</tt> request.
     * 
     * @param transId the transaction ID for this request.
     * @param senderNonce the nonce for this request.
     * @param messageData the <tt>IssuerAndSubject</tt> related to the original <tt>CertificationRequest</tt>.
     */
    public GetCertInitial(TransactionId transId, Nonce senderNonce,
	    IssuerAndSubject messageData) {
	super(transId, MessageType.GET_CERT_INITIAL, senderNonce, messageData);
    }
}
