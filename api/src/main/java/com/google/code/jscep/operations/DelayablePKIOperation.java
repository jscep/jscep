package com.google.code.jscep.operations;

import org.bouncycastle.asn1.DEREncodable;

import com.google.code.jscep.transaction.PkiStatus;

/**
 * This is a marker interface for those PKI operations which may have
 * a {@link PkiStatus.PENDING} response.
 * 
 * @author David Grant
 * @param <T> the type message data for this operation.
 */
public interface DelayablePKIOperation<T extends DEREncodable> extends PKIOperation<T> {

}
