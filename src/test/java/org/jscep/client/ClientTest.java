package org.jscep.client;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.x509.X509Util;
import org.junit.Assume;
import org.junit.Test;

/**
 * These tests are coupled to the ScepServletImpl class
 * 
 * @author David Grant
 */
public class ClientTest extends AbstractClientTest {
    /**
     * The requester MUST use RSA keys for all symmetric key operations.
     *
     * @throws Exception if any error occurs.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testRsa() throws Exception {
        final KeyPair keyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
        final X509Certificate identity = X509Util.createEphemeralCertificate(new X500Principal("CN=jscep.org"), keyPair);
        final URL url = new URL("http://jscep.org/pkiclient.exe");

        new Client(url, identity, keyPair.getPrivate(), new NoSecurityCallbackHandler());
    }

    @Test
    public void testRenewalEnrollAllowed() throws Exception {
        // Ignore this test if the CA doesn't support renewal.
        Assume.assumeTrue(client.getCaCapabilities().isRenewalSupported());

        PKCS10CertificationRequest csr = getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), password);
        Transaction t = client.enrol(csr);
        if (t.send() == State.CERT_ISSUED) {
            t.getCertStore();
        }
    }

    @Test
    public void testEnroll() throws Exception {
    	PKCS10CertificationRequest csr = getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), password);
        Transaction trans = client.enrol(csr);
        State state = trans.send();
        if (state == State.CERT_ISSUED) {
            CertStore store = trans.getCertStore();
            System.out.println(store.getCertificates(null));
        }
    }

    @Test
    public void testEnrollThenGet() throws Exception {
        Transaction trans = client.enrol(getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), password));
        State state = trans.send();
        Assume.assumeTrue(state == State.CERT_ISSUED);
        X509Certificate issued = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
        Certificate retrieved = client.getCertificate(issued.getSerialNumber()).iterator().next();

        assertEquals(issued, retrieved);
    }

    @Test
    public void testEnrollInvalidPassword() throws Exception {
        Transaction trans = client.enrol(getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), new char[0]));
        State state = trans.send();
        
        assertThat(state, is(State.CERT_NON_EXISTANT));
    }

    @Test
    public void cgiProgIsIgnoredForIssue24() throws GeneralSecurityException, MalformedURLException {
        final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final X509Certificate identity = X509Util.createEphemeralCertificate(new X500Principal("CN=jscep.org"), keyPair);
        final URL url = new URL("http://someurl/certsrv/mscep/mscep.dll");

        Client c = new Client(url, identity, keyPair.getPrivate(), new NoSecurityCallbackHandler());
        assertNotNull(c);
    }

    private PKCS10CertificationRequest getCsr(X500Principal subject, PublicKey pubKey, PrivateKey priKey, char[] password) throws GeneralSecurityException, IOException {
        ASN1Set cpSet = new DERSet(new DERPrintableString(new String(password)));
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
        
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner signer;
		try {
			signer = signerBuilder.build(priKey);
		} catch (OperatorCreationException e) {
			IOException ioe = new IOException();
			ioe.initCause(e);
			
			throw ioe;
		}
        
        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(X500Name.getInstance(subject.getEncoded()), pkInfo);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, cpSet);
        
        return builder.build(signer);
    }
}
