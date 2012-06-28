package org.jscep.client;

import java.security.cert.CertStore;

/**
 * Factory for creating X509CertificateTuple objects.
 */
public final class X509CertificateTupleFactory {
    private X509CertificateTupleFactory() {
    }

    /**
     * Creates a new tuple from the given store
     * <p>
     * This method is deprecated. Use X509CertificateTuple.fromCertStore
     * instead.
     * 
     * @param store the store to examine
     * @return a tuple of certificates
     */
    @Deprecated
    public static X509CertificateTuple createTuple(CertStore store) {
        return X509CertificateTuple.fromCertStore(store);
    }
}
