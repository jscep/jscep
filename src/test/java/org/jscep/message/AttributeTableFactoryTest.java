package org.jscep.message;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.jscep.asn1.ScepObjectIdentifiers;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;
import org.junit.Before;
import org.junit.Test;

public class AttributeTableFactoryTest {
    private AttributeTableFactory factory;
    private PkiMessage<?> pkiMessage;
    private PkiResponse<?> pkiFailureResponse;
    private PkiResponse<?> pkiPendingResponse;

    @Before
    public void setUp() {
        TransactionId transId = TransactionId.createTransactionId();
        Nonce nonce = Nonce.nextNonce();
        IssuerAndSerialNumber iasn = mock(IssuerAndSerialNumber.class);
        pkiMessage = new GetCert(transId, nonce, iasn);
        pkiFailureResponse = new CertRep(transId, nonce, nonce, FailInfo.badRequest);
        pkiPendingResponse = new CertRep(transId, nonce, nonce);
        
        factory = new AttributeTableFactory();
    }
    
    @Test
    public void testIsAttributeTable() {
        assertThat(factory.fromPkiMessage(pkiMessage), isA(AttributeTable.class));
    }
    
    @Test
    public void testRequestTransactionIdPresent() {
        AttributeTable table = factory.fromPkiMessage(pkiMessage);
        assertThat(table.get(toOid(ScepObjectIdentifiers.TRANS_ID)), isA(Attribute.class));
    }
    
    @Test
    public void testRequestMessageTypePresent() {
        AttributeTable table = factory.fromPkiMessage(pkiMessage);
        assertThat(table.get(toOid(ScepObjectIdentifiers.MESSAGE_TYPE)), isA(Attribute.class));
    }
    
    @Test
    public void testRequestSenderNoncePresent() {
        AttributeTable table = factory.fromPkiMessage(pkiMessage);
        assertThat(table.get(toOid(ScepObjectIdentifiers.SENDER_NONCE)), isA(Attribute.class));
    }
    
    @Test
    public void testFailureResponsePkiStatusPresent() {
        AttributeTable table = factory.fromPkiMessage(pkiFailureResponse);
        assertThat(table.get(toOid(ScepObjectIdentifiers.PKI_STATUS)), isA(Attribute.class));
    }
    
    @Test
    public void testFailureResponseRecipientNoncePresent() {
        AttributeTable table = factory.fromPkiMessage(pkiFailureResponse);
        assertThat(table.get(toOid(ScepObjectIdentifiers.RECIPIENT_NONCE)), isA(Attribute.class));
    }
    
    @Test
    public void testFailureResponseFailInfoPresent() {
        AttributeTable table = factory.fromPkiMessage(pkiFailureResponse);
        assertThat(table.get(toOid(ScepObjectIdentifiers.FAIL_INFO)), isA(Attribute.class));
    }
    
    @Test
    public void testPendingRequestFailInfoAbsent() {
        AttributeTable table = factory.fromPkiMessage(pkiPendingResponse);
        assertThat(table.get(toOid(ScepObjectIdentifiers.FAIL_INFO)), is(nullValue()));
    }
    
    private ASN1ObjectIdentifier toOid(String oid) {
        return new ASN1ObjectIdentifier(oid);
    }
}
