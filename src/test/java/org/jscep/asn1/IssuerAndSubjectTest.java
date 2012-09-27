package org.jscep.asn1;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class IssuerAndSubjectTest {
    private IssuerAndSubject fixture;
    private X500Name issuer;
    private X500Name subject;

    @Before
    public void setUp() {
        issuer = new X500Name("CN=issuer");
        subject = new X500Name("CN=subject");
        fixture = new IssuerAndSubject(issuer, subject);
    }

    @Test
    public void testSequenceConstructor() {
        final DERSequence seq = (DERSequence) fixture.toASN1Primitive();
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
