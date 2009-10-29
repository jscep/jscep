package com.google.code.jscep;

import com.google.code.jscep.asn1.ScepObjectIdentifiers;
import com.google.code.jscep.request.Operation;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collection;
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
    
    public void handleResponse(CMSSignedData signedData) {
    	SignerInformationStore store = signedData.getSignerInfos();
        Collection<?> signers = store.getSigners();
        for (Object signer : signers) {
            SignerInformation signerInformation = (SignerInformation) signer;
            AttributeTable signedAttrs = signerInformation.getSignedAttributes();

            Attribute transIdAttr = signedAttrs.get(ScepObjectIdentifiers.transId);
            DERPrintableString transId = (DERPrintableString) transIdAttr.getAttrValues().getObjectAt(0);
            Attribute pkiStatusAttribute = signedAttrs.get(ScepObjectIdentifiers.pkiStatus);
            DERPrintableString pkiStatus = (DERPrintableString) pkiStatusAttribute.getAttrValues().getObjectAt(0);
            Attribute msgTypeAttribute = signedAttrs.get(ScepObjectIdentifiers.messageType);
            DERPrintableString msgType = (DERPrintableString) msgTypeAttribute.getAttrValues().getObjectAt(0);
            Attribute senderNoneAttribute = signedAttrs.get(ScepObjectIdentifiers.senderNonce);
            DEROctetString senderNonce = (DEROctetString) senderNoneAttribute.getAttrValues().getObjectAt(0);
            Attribute recipientNonceAttribute = signedAttrs.get(ScepObjectIdentifiers.recipientNonce);
            DEROctetString recipientNonce = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        }
        ContentInfo contentInfo = signedData.getContentInfo();
    }
}
