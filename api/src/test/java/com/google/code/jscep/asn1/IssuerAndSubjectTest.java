package com.google.code.jscep.asn1;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Name;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class IssuerAndSubjectTest {
	private IssuerAndSubject fixture;
	private X509Name issuer;
	private X509Name subject;
	
	@Before
	public void setUp() {
		issuer = new X509Name("CN=issuer");
		subject = new X509Name("CN=subject");
		fixture = new IssuerAndSubject(issuer, subject);
	}

	@Test
	public void testSequenceConstructor() {
		final DERSequence seq = (DERSequence) fixture.getDERObject();
		IssuerAndSubject issuerSubject = new IssuerAndSubject(seq);
		
		Assert.assertEquals(fixture, issuerSubject);
	}
	
	@Test
	public void testGetIssuer() {
		Assert.assertEquals(issuer, fixture.getIssuer());
	}

	@Test
	public void testGetSubject() {
		Assert.assertEquals(subject, fixture.getSubject());
	}
}
