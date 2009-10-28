package com.google.code.jscep;

import com.google.code.jscep.request.Operation;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

public class Transaction {
    private static AtomicLong transactionCounter = new AtomicLong();
    private static Random rnd = new SecureRandom(); 
    private final byte[] transactionId;
    private final byte[] senderNonce = new byte[16];

    {
        rnd.nextBytes(senderNonce);
    }
    
    /**
     * Creates a new enrollment transaction.
     *
     * @param publicKey the public key to enrol.
     */
    public Transaction(PublicKey publicKey) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        transactionId = Hex.encode(digest.digest(publicKey.getEncoded()));
    }

    /**
     * Creates a new non-enrollment transaction.
     */
    public Transaction() {
        transactionId = Long.toHexString(transactionCounter.getAndIncrement()).getBytes();
    }

    public DERPrintableString getTransactionId() {
        return new DERPrintableString(transactionId);
    }

    public DEROctetString getSenderNonce() {
        return new DEROctetString(senderNonce);
    }

    public void performOperation(Operation operation) {
    }
}
