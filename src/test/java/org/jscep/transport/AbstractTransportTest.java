package org.jscep.transport;

import java.math.BigInteger;
import java.net.Proxy;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.eclipse.jetty.server.Server;
import org.jscep.content.CertRepContentHandler;
import org.jscep.message.GetCert;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.request.PKCSReq;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.Transport.Method;
import org.jscep.x509.X509Util;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

abstract public class AbstractTransportTest {
    protected URL url;
    protected Proxy proxy;
    protected Transport transport;
    private Server server;

    @Before
    public void setUp() throws Exception {
        server = new Server(0);
        server.start();
        url = new URL("http://localhost:"
                + server.getConnectors()[0].getLocalPort() + "/");
        proxy = Proxy.NO_PROXY;
        transport = Transport.createTransport(getMethod(), url, proxy);
    }

    abstract protected Method getMethod();

    @After
    public void tearDown() throws Exception {
        server.stop();
    }

    @Test
    public void testGetURL() {
        Assert.assertEquals(url, transport.getURL());
    }

    @Test
    public void test404() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        PkcsPkiEnvelopeEncoder envEnc = new PkcsPkiEnvelopeEncoder(
                getCertificate(keyPair));
        PkiMessageEncoder enc = new PkiMessageEncoder(keyPair.getPrivate(),
                getCertificate(keyPair), envEnc);

        TransactionId transId = TransactionId.createTransactionId();
        Nonce senderNonce = Nonce.nextNonce();
        X500Name name = new X500Name("CN=jscep.org");
        BigInteger serialNumber = BigInteger.ONE;
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name,
                serialNumber);
        GetCert getCert = new GetCert(transId, senderNonce, iasn);
        PKCSReq req = new PKCSReq(enc.encode(getCert));

        try {
            transport.sendRequest(req, new CertRepContentHandler());
        } catch (TransportException e) {
            Assert.assertEquals(e.getMessage(), "404 Not Found");
        }
    }

    private X509Certificate getCertificate(KeyPair keyPair)
            throws GeneralSecurityException {
        final X500Principal subject = new X500Principal("CN=example.org");

        return X509Util.createEphemeralCertificate(subject, keyPair);
    }
}
