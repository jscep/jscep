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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
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
import org.jscep.content.GetCaCapsResponseHandler;
import org.jscep.content.GetCaCertResponseHandler;
import org.jscep.content.GetNextCaCertResponseHandler;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.request.GetCaCapsRequest;
import org.jscep.request.GetCaCertRequest;
import org.jscep.request.GetNextCaCertRequest;
import org.jscep.response.Capabilities;
import org.jscep.transaction.EnrolmentTransaction;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transport.HttpGetTransport;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
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
        Transport transport = new HttpGetTransport(getURL());
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }
        CertStore store = transport.sendRequest(req,
                new GetCaCertResponseHandler(factory));
        Collection<? extends Certificate> certs = store
                .getCertificates(new X509CertSelector());

        if (certs.size() > 0) {
            return (X509Certificate) certs.iterator().next();
        } else {
            return null;
        }
    }

    @Test
    public void testGetCaCaps() throws Exception {
        GetCaCapsRequest req = new GetCaCapsRequest();
        Transport transport = new HttpGetTransport(getURL());
        Capabilities caps = transport.sendRequest(req,
                new GetCaCapsResponseHandler());

        System.out.println(caps);
    }

    @Test
    public void getNextCaCertificateGood() throws Exception {
        GetNextCaCertRequest req = new GetNextCaCertRequest(goodIdentifier);
        Transport transport = new HttpGetTransport(getURL());
        CertStore certs = transport.sendRequest(req,
                new GetNextCaCertResponseHandler(getRecipient()));

        assertThat(certs.getCertificates(null).size(), is(1));
    }

    @Test(expected = TransportException.class)
    public void getNextCaCertificateBad() throws Exception {
        GetNextCaCertRequest req = new GetNextCaCertRequest(badIdentifier);
        Transport transport = new HttpGetTransport(getURL());
        CertStore certs = transport.sendRequest(req,
                new GetNextCaCertResponseHandler(getRecipient()));

        assertThat(certs.getCertificates(null).size(), is(1));
    }

    @Test
    public void testGetCRL() throws Exception {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, goodSerial);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender, priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder, getRecipient());

        Transport transport = new HttpGetTransport(getURL());
        Transaction t = new NonEnrollmentTransaction(transport, encoder,
                decoder, iasn, MessageType.GET_CRL);
        State s = t.send();

        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testGetCertBad() throws Exception {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, badSerial);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender, priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder, getRecipient());

        Transport transport = new HttpGetTransport(getURL());
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
                getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender, priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder, getRecipient());

        Transport transport = new HttpGetTransport(getURL());
        Transaction t = new EnrolmentTransaction(transport, encoder, decoder,
                csr);

        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testEnrollmentPost() throws Exception {
        PKCS10CertificationRequest csr = getCsr(name, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender, priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder, getRecipient());

        Transport transport = new HttpGetTransport(getURL());
        Transaction t = new EnrolmentTransaction(transport, encoder, decoder,
                csr);

        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testEnrollmentWithPoll() throws Exception {
        PKCS10CertificationRequest csr = getCsr(pollName, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender, priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder, getRecipient());

        Transport transport = new HttpGetTransport(getURL());
        EnrolmentTransaction trans = new EnrolmentTransaction(transport,
                encoder, decoder, csr);
        State state = trans.send();
        assertThat(state, is(State.CERT_REQ_PENDING));

        trans.setIssuer(sender);
        state = trans.poll();
        assertThat(state, is(State.CERT_REQ_PENDING));
    }

    private PKCS10CertificationRequest getCsr(X500Name subject,
            PublicKey pubKey, PrivateKey priKey, char[] password)
            throws GeneralSecurityException, IOException {
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey
                .getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
                "SHA1withRSA");
        ContentSigner signer;
        try {
            signer = signerBuilder.build(priKey);
        } catch (OperatorCreationException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
                subject, pkInfo);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                new DERPrintableString(new String(password)));

        return builder.build(signer);
    }
}
