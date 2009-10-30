package com.google.code.jscep;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.encoders.Hex;

import com.google.code.jscep.asn1.PkiStatus;
import com.google.code.jscep.asn1.ScepObjectIdentifiers;
import com.google.code.jscep.request.GetCRL;
import com.google.code.jscep.request.Operation;
import com.google.code.jscep.transport.Transport;

public class Transaction {
    private static AtomicLong transactionCounter = new AtomicLong();
    private static Random rnd = new SecureRandom(); 
    private final byte[] transactionId;
    private final byte[] senderNonce = new byte[16];
    private int status;
    private int reason;
    private Operation operation;
    private List<X509CRL> crls;
    private List<X509Certificate> certs;

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
    
    public int getStatus() {
    	return status;
    }
    
    public int getFailureReason() {
    	return reason;
    }

    public DERPrintableString getTransactionId() {
        return new DERPrintableString(transactionId);
    }

    public DEROctetString getSenderNonce() {
        return new DEROctetString(senderNonce);
    }

    public CertStore performOperation(URL url, Proxy proxy, Operation operation) throws MalformedURLException, IOException, ScepException {
    	this.operation = operation;
    	
    	operation.setSenderNonce(getSenderNonce());
    	operation.setTransactionId(getTransactionId());
    	
    	Transport transport = Transport.createTransport("POST", url, proxy);
    	CMSSignedData signedData = (CMSSignedData) transport.sendMessage(operation);
    	
    	return handleResponse(signedData);
    }
    
    public CertStore handleResponse(CMSSignedData signedData) throws ScepException {
    	SignerInformationStore store = signedData.getSignerInfos();
        Collection<?> signers = store.getSigners();
        
        if (signers.size() > 1) {
        	throw new ScepException("Too Many SignerInfos");
        }
        SignerInformation signerInformation = (SignerInformation) signers.iterator().next();
        AttributeTable signedAttrs = signerInformation.getSignedAttributes();

        Attribute transIdAttr = signedAttrs.get(ScepObjectIdentifiers.transId);
        DERPrintableString transId = (DERPrintableString) transIdAttr.getAttrValues().getObjectAt(0);
        if (transId.equals(getTransactionId()) == false) {
            throw new ScepException("Transaction ID Mismatch: Sent [" + getTransactionId() + "]; Received [" + transId + "]");
        }
        
        Attribute msgTypeAttribute = signedAttrs.get(ScepObjectIdentifiers.messageType);
        DERPrintableString msgType = (DERPrintableString) msgTypeAttribute.getAttrValues().getObjectAt(0);
        if (msgType.getString().equals("3") == false) {
        	throw new ScepException("Invalid Message Type: " + msgType);
        }
        
        Attribute senderNoneAttribute = signedAttrs.get(ScepObjectIdentifiers.senderNonce);
        DEROctetString senderNonce = (DEROctetString) senderNoneAttribute.getAttrValues().getObjectAt(0);
        
        Attribute recipientNonceAttribute = signedAttrs.get(ScepObjectIdentifiers.recipientNonce);
        DEROctetString recipientNonce = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        if (recipientNonce.equals(getSenderNonce()) == false) {
        	throw new ScepException("Sender Nonce Mismatch.  Sent [" + getSenderNonce() + "]; Received [" + recipientNonce + "]");
        }
        
        Attribute pkiStatusAttribute = signedAttrs.get(ScepObjectIdentifiers.pkiStatus);
        DERPrintableString pkiStatus = (DERPrintableString) pkiStatusAttribute.getAttrValues().getObjectAt(0);
        
        status = Integer.parseInt(pkiStatus.toString());
        
        if (status == PkiStatus.FAILURE) {
        	
        	Attribute failInfoAttribute = signedAttrs.get(ScepObjectIdentifiers.failInfo);
        	DERPrintableString failInfo = (DERPrintableString) failInfoAttribute.getAttrValues().getObjectAt(0);
        	
        	reason = Integer.parseInt(failInfo.toString());
        	return null;
        } else if (status == PkiStatus.PENDING) {
        	return null;
        }
        
        try {
			return signedData.getCertificatesAndCRLs("Collection", "BC");
		} catch (CMSException e) {
			throw new ScepException(e);
		} catch (GeneralSecurityException e) {
			throw new ScepException(e);
		}
    }
    
    public List<X509CRL> getCRLs() {
    	return crls; 
    }
    
    public List<X509Certificate> getCertificates() {
    	return certs;
    }
}
