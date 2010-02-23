package org.jscep.operations;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.bouncycastle.asn1.x509.X509Name;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.operations.GetCertInitial;
import org.jscep.operations.PKIOperation;
import org.jscep.transaction.MessageType;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class GetCertInitialTest {
	private PKIOperation<IssuerAndSubject> fixture;
	private X509Name issuer;
	private X509Name subject;
	
	@Before
	public void setUp() {
		issuer = new X509Name("CN=issuer");
		subject = new X509Name("CN=subject");
		fixture = new GetCertInitial(issuer, subject);
	}

	@Test
	public void testGetMessageType() {
		Assert.assertSame(MessageType.GetCertInitial, fixture.getMessageType());
	}

	@Test
	public void testGetMessageData() throws IOException, GeneralSecurityException {
		final IssuerAndSubject ias = new IssuerAndSubject(issuer, subject);
		
		Assert.assertEquals(ias, fixture.getMessage());
	}

}
