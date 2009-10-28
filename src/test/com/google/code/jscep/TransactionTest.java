package com.google.code.jscep;

import junit.framework.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;

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

        Assert.assertFalse(Arrays.equals(a.getTransactionId(), b.getTransactionId()));
    }

    @Test
    public void testGetTransactionIdEquals() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = generator.generateKeyPair();
        Transaction a = new Transaction(keyPair.getPublic());
        Transaction b = new Transaction(keyPair.getPublic());

        Assert.assertTrue(Arrays.equals(a.getTransactionId(), b.getTransactionId()));
    }

    @Test
    public void testGetSenderNonce() throws Exception {
        Transaction a = new Transaction();
        Transaction b = new Transaction();

        Assert.assertFalse(Arrays.equals(a.getSenderNonce(), b.getSenderNonce()));
    }
}
