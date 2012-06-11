package org.jscep.client;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@RunWith(Parameterized.class)
public class X509CertificateTupleFactoryTest {
    @Parameterized.Parameters
    public static Collection<Object[]> setUp() throws Exception {
        InputStream keyStoreIn = X509CertificateTupleFactoryTest.class.getClassLoader().getResourceAsStream("store.jks");
        KeyStore testStore = KeyStore.getInstance("JKS");
        testStore.load(keyStoreIn, "password".toCharArray());

        List<Object[]> configs = new ArrayList<Object[]>();

        configs.add(new Object[]{"ca", "ca", "ca", "ca"});
        configs.add(new Object[]{"ca_ra", "ca_ra", "ca_ra", "ca"});
        configs.add(new Object[]{"ca_ra-de", "ca_ra-de", "ca", "ca"});
        configs.add(new Object[]{"ca_ra-ds", "ca", "ca_ra-ds", "ca"});
        configs.add(new Object[]{"ca_ca", "ca_ca", "ca_ca", "ca_ca"});
        configs.add(new Object[]{"ca_ca_ra", "ca_ca_ra", "ca_ca_ra", "ca_ca"});
        configs.add(new Object[]{"ca_ca_ra-de", "ca_ca_ra-de", "ca_ca", "ca_ca"});
        configs.add(new Object[]{"ca_ca_ra-ds", "ca_ca", "ca_ca_ra-ds", "ca_ca"});

        for (Object[] config : configs) {
            Certificate[] chain = testStore.getCertificateChain((String) config[0]);
            List<Certificate> certList = Arrays.asList(chain);
            CertStoreParameters storeParams = new CollectionCertStoreParameters(certList);
            CertStore store = CertStore.getInstance("Collection", storeParams);

            config[0] = store;
            config[1] = "CN=" + config[1];
            config[2] = "CN=" + config[2];
            config[3] = "CN=" + config[3];
        }

        return configs;
    }

    private CertStore store;
    private String encryption;
    private String signing;
    private String issuer;

    public X509CertificateTupleFactoryTest(CertStore store, String encryption, String signing, String issuer) {
        this.store = store;
        this.encryption = encryption;
        this.signing = signing;
        this.issuer = issuer;
    }

    @Test
    public void example() {
        X509CertificateTuple certPair = X509CertificateTupleFactory.createTuple(store);

        Assert.assertEquals(encryption, certPair.getEncryption().getSubjectDN().getName());
        Assert.assertEquals(signing, certPair.getVerification().getSubjectDN().getName());
        Assert.assertEquals(issuer, certPair.getIssuer().getSubjectDN().getName());
    }
}
