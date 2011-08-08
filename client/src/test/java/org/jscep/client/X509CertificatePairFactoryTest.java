package org.jscep.client;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;

@RunWith(Parameterized.class)
public class X509CertificatePairFactoryTest {
    @Parameterized.Parameters
    public static Collection<Object[]> setUp() throws Exception {
        InputStream keyStoreIn = X509CertificatePairFactoryTest.class.getClassLoader().getResourceAsStream("store.jks");
        KeyStore testStore = KeyStore.getInstance("JKS");
        testStore.load(keyStoreIn, "password".toCharArray());
        Enumeration<String> aliases = testStore.aliases();

        List<Object[]> configs = new ArrayList<Object[]>();

        configs.add(new Object[] {"ca", "ca", "ca"});
        configs.add(new Object[] {"ca_ra", "ca_ra", "ca_ra"});
        configs.add(new Object[]{"ca_ra-de", "ca_ra-de", "ca"});
        configs.add(new Object[]{"ca_ra-ds", "ca", "ca_ra-ds"});
        configs.add(new Object[]{"ca_ca", "ca_ca", "ca_ca"});
        configs.add(new Object[]{"ca_ca_ra", "ca_ca_ra", "ca_ca_ra"});
        configs.add(new Object[]{"ca_ca_ra-de", "ca_ca_ra-de", "ca_ca"});
        configs.add(new Object[]{"ca_ca_ra-ds", "ca_ca", "ca_ca_ra-ds"});

        for (Object[] config : configs) {
            Certificate[] chain = testStore.getCertificateChain((String) config[0]);
            List<Certificate> certList = Arrays.asList(chain);
            CertStoreParameters storeParams = new CollectionCertStoreParameters(certList);
            CertStore store = CertStore.getInstance("Collection", storeParams);

            config[0] = store;
            config[1] = "CN=" + config[1];
            config[2] = "CN=" + config[2];
        }

        return configs;
    }

    private CertStore store;
    private String encryption;
    private String signing;

    public X509CertificatePairFactoryTest(CertStore store, String encryption, String signing) {
        this.store = store;
        this.encryption = encryption;
        this.signing = signing;
    }

    @Test
    public void example() {
        X509CertificatePair certPair = X509CertificatePairFactory.createPair(store);

        Assert.assertEquals(encryption, certPair.getEncryption().getSubjectDN().getName());
        Assert.assertEquals(signing, certPair.getSigning().getSubjectDN().getName());
    }
}
