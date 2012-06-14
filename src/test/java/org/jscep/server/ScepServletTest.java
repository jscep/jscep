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
import java.security.Signature;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.jscep.content.CaCapabilitiesContentHandler;
import org.jscep.content.CaCertificateContentHandler;
import org.jscep.content.NextCaCertificateContentHandler;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.request.GetCaCaps;
import org.jscep.request.GetCaCert;
import org.jscep.request.GetNextCaCert;
import org.jscep.response.Capabilities;
import org.jscep.transaction.EnrolmentTransaction;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transport.Transport;
import org.jscep.transport.Transport.Method;
import org.jscep.transport.TransportException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ScepServletTest {
    private static String PATH = "/scep/pkiclient.exe";
    private BigInteger goodSerial;
    private BigInteger badSerial;
    private X509Name name;
    private X509Name pollName;
    private PrivateKey priKey;
    private PublicKey pubKey;
    private X509Certificate sender;
    private Server server;
    private int port;
    private String goodIdentifier;
    private String badIdentifier;

    @Before
    public void configureFixtures() throws Exception {
        name = new X509Name("CN=Example");
        pollName = new X509Name("CN=Poll");
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
        X509V1CertificateGenerator generator = new X509V1CertificateGenerator();
        generator.setIssuerDN(name);
        generator.setNotAfter(new Date());
        generator.setNotBefore(new Date());
        generator.setPublicKey(pubKey);
        generator.setSerialNumber(goodSerial);
        generator.setSignatureAlgorithm("SHA1withRSA");
        generator.setSubjectDN(name);

        return generator.generate(priKey);
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
        GetCaCert req = new GetCaCert();
        Transport transport = Transport.createTransport(Method.GET, getURL());
        CertificateFactory factory;
		try {
			factory = CertificateFactory.getInstance("X509");
		} catch (CertificateException e) {
			throw new IOException(e);
		}
        CertStore store = transport.sendRequest(req, new CaCertificateContentHandler(factory));
        Collection<? extends Certificate> certs = store.getCertificates(new X509CertSelector());

        if (certs.size() > 0) {
            return (X509Certificate) certs.iterator().next();
        } else {
            return null;
        }
    }

    @Test
    public void testGetCaCaps() throws Exception {
        GetCaCaps req = new GetCaCaps();
        Transport transport = Transport.createTransport(Method.GET, getURL());
        Capabilities caps = transport.sendRequest(req, new CaCapabilitiesContentHandler());

        System.out.println(caps);
    }

    @Test
    public void getNextCaCertificateGood() throws Exception {
        GetNextCaCert req = new GetNextCaCert(goodIdentifier);
        Transport transport = Transport.createTransport(Method.GET, getURL());
        List<X509Certificate> certs = transport.sendRequest(req, new NextCaCertificateContentHandler(getRecipient()));

        assertThat(certs.size(), is(1));
    }

    @Test(expected = TransportException.class)
    public void getNextCaCertificateBad() throws Exception {
        GetNextCaCert req = new GetNextCaCert(badIdentifier);
        Transport transport = Transport.createTransport(Method.GET, getURL());
        List<X509Certificate> certs = transport.sendRequest(req, new NextCaCertificateContentHandler(getRecipient()));
        
        assertThat(certs.size(), is(1));
    }

    @Test
    public void testGetCRL() throws Exception {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, goodSerial);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender, envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder);

        Transport transport = Transport.createTransport(Method.GET, getURL());
        NonEnrollmentTransaction t = new NonEnrollmentTransaction(transport, encoder, decoder, iasn, MessageType.GET_CRL);
        State s = t.send();

        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testGetCertBad() throws Exception {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, badSerial);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender, envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder);

        Transport transport = Transport.createTransport(Method.GET, getURL());
        NonEnrollmentTransaction t = new NonEnrollmentTransaction(transport, encoder, decoder, iasn, MessageType.GET_CERT);
        State s = t.send();
        
        assertThat(s, is(State.CERT_NON_EXISTANT));
    }

    @Test
    public void testEnrollmentGet() throws Exception {
        CertificationRequest csr = getCsr(name, pubKey, priKey, "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender, envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder);

        Transport transport = Transport.createTransport(Method.GET, getURL());
        EnrolmentTransaction t = new EnrolmentTransaction(transport, encoder, decoder, csr);

        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testEnrollmentPost() throws Exception {
        CertificationRequest csr = getCsr(name, pubKey, priKey, "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender, envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder);

        Transport transport = Transport.createTransport(Method.POST, getURL());
        EnrolmentTransaction t = new EnrolmentTransaction(transport, encoder, decoder, csr);
        
        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testEnrollmentWithPoll() throws Exception {
        CertificationRequest csr = getCsr(pollName, pubKey, priKey, "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(getRecipient());
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender, envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder);

        Transport transport = Transport.createTransport(Method.POST, getURL());
        EnrolmentTransaction trans = new EnrolmentTransaction(transport, encoder, decoder, csr);
        State state = trans.send();
        assertThat(state, is(State.CERT_REQ_PENDING));
        
        trans.setIssuer(sender);
        state = trans.poll();
        assertThat(state, is(State.CERT_REQ_PENDING));
    }

    private CertificationRequest getCsr(X509Name subject, PublicKey pubKey, PrivateKey priKey, char[] password) throws GeneralSecurityException, IOException {
        AlgorithmIdentifier sha1withRsa = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);

        ASN1Set cpSet = new DERSet(new DERPrintableString(new String(password)));
        Attribute challengePassword = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, cpSet);
        ASN1Set attrs = new DERSet(challengePassword);

        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo((ASN1Sequence) ASN1Object.fromByteArray(pubKey.getEncoded()));
        CertificationRequestInfo requestInfo = new CertificationRequestInfo(subject, pkInfo, attrs);

        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(priKey);
        signer.update(requestInfo.getEncoded());
        byte[] signatureBytes = signer.sign();
        DERBitString signature = new DERBitString(signatureBytes);

        return new CertificationRequest(requestInfo, sha1withRsa, signature);
    }
}
