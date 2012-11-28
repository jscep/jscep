package org.jscep.client.inspect;

import java.security.cert.CertStore;

public class DefaultCertStoreInspectorTest extends CertStoreInspectorTest {
    public DefaultCertStoreInspectorTest(final CertStore store, final String encryption,
            final String signing, final String issuer) {
        super(store, encryption, signing, issuer);
    }

    @Override
    CertStoreInspectorFactory getCertStoreInspectorFactory() {
        return new DefaultCertStoreInspectorFactory();
    }
}
