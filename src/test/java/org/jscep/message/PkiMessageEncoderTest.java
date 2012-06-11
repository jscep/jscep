package org.jscep.message;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;
import org.jscep.x509.X509Util;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

public class PkiMessageEncoderTest {
    @Test
    public void simpleTest() throws Exception {
        KeyPair caPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate ca = X509Util.createEphemeralCertificate(new X500Principal("CN=CA"), caPair);

        KeyPair clientPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate client = X509Util.createEphemeralCertificate(new X500Principal("CN=Client"), clientPair);

        TransactionId transId = TransactionId.createTransactionId(clientPair.getPublic(), "SHA-1");
        Nonce senderNonce = Nonce.nextNonce();
        IssuerAndSubject messageData = new IssuerAndSubject(new X509Name("CN=CA"), new X509Name("CN=Client"));

//		GetCRL crl = new GetCRL(transId, senderNonce, messageData);
        GetCertInitial outgoingMessage = new GetCertInitial(transId, senderNonce, messageData);

        // Everything below this line only available to client

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(ca);
        PkiMessageEncoder encoder = new PkiMessageEncoder(clientPair.getPrivate(), client, envEncoder);
        CMSSignedData scepMessage = encoder.encode(outgoingMessage);

        // Everything below this line only available to CA

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(caPair.getPrivate());
        PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder);
        PkiMessage<? extends ASN1Encodable> incomingMessage = decoder.decode(scepMessage);

        System.out.println(incomingMessage);
    }
}
