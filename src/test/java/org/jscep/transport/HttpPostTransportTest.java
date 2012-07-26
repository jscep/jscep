package org.jscep.transport;

import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.jscep.transport.request.GetCaCapsRequest;
import org.jscep.transport.request.GetCaCertRequest;
import org.jscep.transport.request.GetNextCaCertRequest;
import org.jscep.transport.response.GetNextCaCertResponseHandler;
import org.jscep.util.X509Certificates;
import org.junit.Test;

public class HttpPostTransportTest extends AbstractTransportTest {
    @Test(expected = IllegalArgumentException.class)
    public void testGetCACert() throws Exception {
        transport.sendRequest(new GetCaCertRequest(), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetCACaps() throws Exception {
        transport.sendRequest(new GetCaCapsRequest(), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetNextCACert() throws Exception {
        X500Principal subject = new X500Principal("CN=example.org");
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate cert = X509Certificates.createEphemeral(subject,
                keyPair);

        GetNextCaCertRequest nextCa = new GetNextCaCertRequest();
        transport
                .sendRequest(nextCa, new GetNextCaCertResponseHandler(cert));
    }

    @Override
    protected Transport getTransport(URL url) {
        return new HttpPostTransport(url);
    }
}
