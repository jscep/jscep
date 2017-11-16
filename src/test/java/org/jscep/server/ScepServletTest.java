package org.jscep.server;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.EnrollmentTransaction;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
import org.jscep.transport.TransportFactory;
import org.jscep.transport.TransportFactory.Method;
import org.jscep.transport.UrlConnectionTransportFactory;
import org.jscep.transport.request.GetCaCapsRequest;
import org.jscep.transport.request.GetCaCertRequest;
import org.jscep.transport.request.GetNextCaCertRequest;
import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.GetCaCapsResponseHandler;
import org.jscep.transport.response.GetCaCertResponseHandler;
import org.jscep.transport.response.GetNextCaCertResponseHandler;
import org.jscep.util.X500Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ScepServletTest {
    private static String PATH = "/scep/pkiclient.exe";
    private BigInteger goodSerial;
    private BigInteger badSerial;
    private X500Name name;
    private X500Name pollName;
    private PrivateKey priKey;
    private PublicKey pubKey;
    private X509Certificate sender;
    private Server server;
    private int port;
    private String goodIdentifier;
    private String badIdentifier;
    private TransportFactory transportFactory;

    @Before
    public void configureFixtures() throws Exception {
        name = new X500Name("CN=Example");
        pollName = new X500Name("CN=Poll");
        goodSerial = BigInteger.ONE;
        badSerial = BigInteger.ZERO;
        goodIdentifier = null;
        badIdentifier = "bad";
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        priKey = keyPair.getPrivate();
        pubKey = keyPair.getPublic();
        sender = generateCertificate();
        transportFactory = new UrlConnectionTransportFactory();

    }

    private X509Certificate generateCertificate() throws Exception {
        ContentSigner signer;
        try {
            signer = new JcaContentSignerBuilder("SHA1withRSA").build(priKey);
        } catch (OperatorCreationException e) {
            throw new Exception(e);
        }
        Calendar cal = GregorianCalendar.getInstance();
        cal.add(Calendar.YEAR, -1);
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, 2);
        Date notAfter = cal.getTime();
        JcaX509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(
                name, BigInteger.ONE, notBefore, notAfter, name, pubKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    @Before
    public void startUp() throws Exception {
        final ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(ScepServletImpl.class, PATH);

        server = new Server(0);
        server.setHandler(handler);
        server.start();

        port = server.getConnectors()[0].getLocalPort();
    }

    @After
    public void shutDown() throws Exception {
        server.stop();
    }

    private URL getURL() throws MalformedURLException {
        return new URL("http", "localhost", port, PATH);
    }

    private X509Certificate getRecipient() throws Exception {
        GetCaCertRequest req = new GetCaCertRequest();
        Transport transport = getTransport(getURL());

        CertStore store = transport.sendRequest(req,
                new GetCaCertResponseHandler());
        Collection<? extends Certificate> certs = store.getCertificates(null);

        if (certs.size() > 0) {
            return (X509Certificate) certs.iterator().next();
        } else {
            return null;
        }
    }

    @Test
    public void testGetCaCaps() throws Exception {
        GetCaCapsRequest req = new GetCaCapsRequest();
        Transport transport = getTransport(getURL());
        Capabilities caps = transport.sendRequest(req,
                new GetCaCapsResponseHandler());

        System.out.println(caps);
    }

    @Test
    public void getNextCaCertificateGood() throws Exception {
        GetNextCaCertRequest req = new GetNextCaCertRequest(goodIdentifier);
        Transport transport = getTransport(getURL());
        CertStore certs = transport.sendRequest(req,
                new GetNextCaCertResponseHandler(getRecipient()));

        assertThat(certs.getCertificates(null).size(), is(1));
    }

    @Test(expected = TransportException.class)
    public void getNextCaCertificateBad() throws Exception {
        GetNextCaCertRequest req = new GetNextCaCertRequest(badIdentifier);
        Transport transport = getTransport(getURL());
        CertStore certs = transport.sendRequest(req,
                new GetNextCaCertResponseHandler(getRecipient()));

        assertThat(certs.getCertificates(null).size(), is(1));
    }

    @Test
    public void testGetCRL() throws Exception {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, goodSerial);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DESede");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        Transaction t = new NonEnrollmentTransaction(transport, encoder,
                decoder, iasn, MessageType.GET_CRL);
        State s = t.send();

        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testGetCertBad() throws Exception {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, badSerial);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        Transaction t = new NonEnrollmentTransaction(transport, encoder,
                decoder, iasn, MessageType.GET_CERT);
        State s = t.send();

        assertThat(s, is(State.CERT_NON_EXISTANT));
    }

    @Test
    public void testEnrollmentGet() throws Exception {
        PKCS10CertificationRequest csr = getCsr(name, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DESede");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        Transaction t = new EnrollmentTransaction(transport, encoder, decoder,
                csr);

        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testEnrollmentPost() throws Exception {
        PKCS10CertificationRequest csr = getCsr(name, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = transportFactory.forMethod(Method.POST, getURL());
        Transaction t = new EnrollmentTransaction(transport, encoder, decoder,
                csr);

        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testEnrollmentWithPoll() throws Exception {
        PKCS10CertificationRequest csr = getCsr(pollName, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        EnrollmentTransaction trans = new EnrollmentTransaction(transport,
                encoder, decoder, csr);
        State state = trans.send();
        assertThat(state, is(State.CERT_REQ_PENDING));

        IssuerAndSubject ias = new IssuerAndSubject(X500Utils.toX500Name(sender
                .getIssuerX500Principal()), pollName);
        trans = new EnrollmentTransaction(transport, encoder, decoder, ias,
                trans.getId());
        state = trans.send();
        assertThat(state, is(State.CERT_REQ_PENDING));
    }

    @Test
    public void testEnrollmentNotAuthorized() throws Exception {
        PKCS10CertificationRequest csr = getCsr(name, pubKey, priKey);

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = transportFactory.forMethod(Method.POST, getURL());
        Transaction t = new EnrollmentTransaction(transport, encoder, decoder,
                csr);

        State s = t.send();
        assertThat(s, is(State.CERT_NON_EXISTANT));
        assertThat(t.getFailInfo(), is(FailInfo.badRequest));
    }

    @Test
    public void testRenewal() throws Exception {
        PKCS10CertificationRequest csr = getCsr(name, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = transportFactory.forMethod(Method.POST, getURL());
        Transaction t = new EnrollmentTransaction(transport, encoder, decoder,
                csr);

        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
        Certificate[] certificateChain = t.getCertStore()
                .getCertificates(null)
                .toArray(new Certificate[0]);
        X509Certificate prevCertificate =
                (X509Certificate) certificateChain[certificateChain.length - 1];

        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        PrivateKey newPriKey = keyPair.getPrivate();
        PublicKey newPubKey = keyPair.getPublic();
        csr = getCsr(name, newPubKey, newPriKey);
        encoder = new PkiMessageEncoder(priKey, prevCertificate, envEncoder);
        envDecoder = new PkcsPkiEnvelopeDecoder(prevCertificate, priKey);
        decoder = new PkiMessageDecoder(getRecipient(), envDecoder);
        t = new EnrollmentTransaction(transport, encoder, decoder, csr);
        State renewalSate = t.send();
        assertThat(renewalSate, is(State.CERT_ISSUED));
    }

    private PKCS10CertificationRequest getCsr(
            X500Name subject, PublicKey pubKey, PrivateKey priKey
    ) throws GeneralSecurityException, IOException {
        return csrBuilder(subject, pubKey)
                .build(getContentSigner(priKey));
    }

    private PKCS10CertificationRequest getCsr(
            X500Name subject, PublicKey pubKey, PrivateKey priKey,
            char[] password
    ) throws GeneralSecurityException, IOException {
        return csrBuilder(subject, pubKey)
                .addAttribute(
                        PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                        new DERPrintableString(new String(password))
                )
                .build(getContentSigner(priKey));
    }

    private PKCS10CertificationRequestBuilder csrBuilder(
            X500Name subject, PublicKey pubKey
    ) {
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey
                .getEncoded());
        return new PKCS10CertificationRequestBuilder(subject, pkInfo);
    }

    private ContentSigner getContentSigner(PrivateKey priKey)
            throws IOException {
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
                "SHA1withRSA"
        );
        try {
            return signerBuilder.build(priKey);
        } catch (OperatorCreationException e) {
            throw new IOException(e);
        }
    }

    private Transport getTransport(URL url) {
        return transportFactory.forMethod(Method.GET, url);
    }
}
