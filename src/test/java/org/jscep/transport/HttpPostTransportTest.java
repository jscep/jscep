package org.jscep.transport;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.jscep.content.NextCaCertificateContentHandler;
import org.jscep.request.GetCaCaps;
import org.jscep.request.GetCaCert;
import org.jscep.request.GetNextCaCert;
import org.jscep.transport.Transport.Method;
import org.jscep.x509.X509Util;
import org.junit.Test;


public class HttpPostTransportTest extends AbstractTransportTest {
    @Test(expected = IllegalArgumentException.class)
    public void testGetCACert() throws Exception {
        transport.sendRequest(new GetCaCert(), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetCACaps() throws Exception {
        transport.sendRequest(new GetCaCaps(), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetNextCACert() throws Exception {
        X500Principal subject = new X500Principal("CN=example.org");
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate cert = X509Util.createEphemeralCertificate(subject, keyPair);

        GetNextCaCert nextCa = new GetNextCaCert();
        transport.sendRequest(nextCa, new NextCaCertificateContentHandler(cert));
    }

    @Override
    protected Method getMethod() {
        return Method.POST;
    }
}
