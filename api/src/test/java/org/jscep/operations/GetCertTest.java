package org.jscep.operations;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.jscep.operations.GetCert;
import org.jscep.operations.PKIOperation;
import org.jscep.transaction.MessageType;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class GetCertTest {
	private PKIOperation<IssuerAndSerialNumber> fixture;
	private X500Principal issuer;
	private BigInteger serial;
	
	@Before
	public void setUp() {
		issuer = new X500Principal("CN=issuer");
		serial = BigInteger.ZERO;
		fixture = new GetCert(issuer, serial);
	}

	@Test
	public void testGetMessageType() {
		Assert.assertSame(MessageType.GetCert, fixture.getMessageType());
	}

	@Test
	public void testGetMessageData() throws IOException, GeneralSecurityException {
		final X509Name name = new X509Principal(issuer.getEncoded());
		final IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
		
		Assert.assertEquals(iasn, fixture.getMessage());
	}

}
