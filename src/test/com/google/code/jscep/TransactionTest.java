package com.google.code.jscep;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

public class TransactionTest {
    private Transaction trans;

    @Before
    public void setUp() {
        trans = new Transaction();
    }

    @Test
    public void testGetTransactionId() throws Exception {
        Transaction a = new Transaction();
        Transaction b = new Transaction();

        Assert.assertFalse(a.getTransactionId().equals(b.getTransactionId()));
    }

    @Test
    public void testGetTransactionIdEquals() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = generator.generateKeyPair();
        Transaction a = new Transaction(keyPair.getPublic());
        Transaction b = new Transaction(keyPair.getPublic());

        Assert.assertTrue(a.getTransactionId().equals(b.getTransactionId()));
    }

    @Test
    public void testGetSenderNonce() throws Exception {
        Transaction a = new Transaction();
        Transaction b = new Transaction();

        Assert.assertFalse(a.getSenderNonce().equals(b.getSenderNonce()));
    }
}
