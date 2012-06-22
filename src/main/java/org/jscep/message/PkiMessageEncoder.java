/*
 * Copyright (c) 2010 ThruPoint Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.message;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PkiMessageEncoder {
    private static final Logger LOGGER = LoggerFactory.getLogger(PkiMessageEncoder.class);
    private final PrivateKey senderKey;
    private final X509Certificate senderCert;
    private final PkcsPkiEnvelopeEncoder encoder;

    public PkiMessageEncoder(PrivateKey priKey, X509Certificate sender, PkcsPkiEnvelopeEncoder enveloper) {
        this.senderKey = priKey;
        this.senderCert = sender;
        this.encoder = enveloper;
    }

    public byte[] encode(PkiMessage<?> message) throws IOException {
        LOGGER.debug("Encoding message: {}", message);
        CMSProcessableByteArray signable;

        boolean hasMessageData = true;
        if (message instanceof PkiResponse<?>) {
            PkiResponse<?> response = (PkiResponse<?>) message;
            if (response.getPkiStatus() != PkiStatus.SUCCESS) {
                hasMessageData = false;
            }
        }
        if (hasMessageData) {
        	byte[] ed;
        	if (message.getMessageData() instanceof byte[]) {
        		ed = encoder.encode((byte[]) message.getMessageData());
        	} else if (message.getMessageData() instanceof PKCS10CertificationRequest) {
        		ed = encoder.encode(((PKCS10CertificationRequest) message.getMessageData()).getEncoded());
        	} else {
        		ed = encoder.encode(((ASN1Object) message.getMessageData()).getEncoded());
        	}
            signable = new CMSProcessableByteArray(ed);
        } else {
            signable = null;
        }

        Hashtable<DERObjectIdentifier, Attribute> table = new Hashtable<DERObjectIdentifier, Attribute>();
        for (Map.Entry<String, Object> entry : message.getAttributes().entrySet()) {
        	ASN1ObjectIdentifier oid = toOid(entry.getKey());
        	table.put(oid, new Attribute(oid, toSet(entry.getValue())));
        }
//        table.put(PKCSObjectIdentifiers.pkcs_9_at_contentType, new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType, toSet(PKCSObjectIdentifiers.data)));
//        table.put(PKCSObjectIdentifiers.pkcs_9_at_messageDigest, new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest, toSet(PKCSObjectIdentifiers.sha1WithRSAEncryption)));
        AttributeTable signedAttrs = new AttributeTable(table);
        Collection<X509Certificate> certColl = Collections.singleton(senderCert);
        JcaCertStore store;
		try {
			store = new JcaCertStore(certColl);
		} catch (CertificateEncodingException e) {
			IOException ioe = new IOException();
        	ioe.initCause(e);
        	
            throw ioe;
		}

        CMSSignedDataGenerator sdGenerator = new CMSSignedDataGenerator();
        LOGGER.debug("Signing message using key belonging to '{}'", senderCert.getSubjectDN());
//        sdGenerator.addSigner(senderKey, senderCert, CMSSignedGenerator.DIGEST_SHA1, signedAttrs, null);
        try {
	        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
	        CMSAttributeTableGenerator signedGen = new DefaultSignedAttributeTableGenerator(signedAttrs);
	        builder.setSignedAttributeGenerator(signedGen);
	        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
	        SignerInfoGenerator infoGen = builder.build(contentSignerBuilder.build(senderKey), senderCert);
	        sdGenerator.addSignerInfoGenerator(infoGen);
        } catch (CertificateEncodingException e) {
        	IOException ioe = new IOException();
        	ioe.initCause(e);
        	
            throw ioe;
		} catch (OperatorCreationException e) {
			IOException ioe = new IOException();
        	ioe.initCause(e);
        	
            throw ioe;
		}
        try {
            sdGenerator.addCertificates(store);
        } catch (Exception e) {
        	IOException ioe = new IOException();
        	ioe.initCause(e);
        	
            throw ioe;
        }

        LOGGER.debug("Signing {} content", signable);
        CMSSignedData sd;
		try {
			sd = sdGenerator.generate((String) "1.2.840.113549.1.7.1", signable, true, Security.getProvider("BC"), true);
		} catch (NoSuchAlgorithmException e) {
			IOException ioe = new IOException();
        	ioe.initCause(e);
        	
            throw ioe;
		} catch (CMSException e) {
			IOException ioe = new IOException();
        	ioe.initCause(e);
        	
            throw ioe;
		}
        LOGGER.debug("Encoded to: {}", sd.getEncoded());
        return sd.getEncoded();
    }
    
    private ASN1ObjectIdentifier toOid(String oid) {
		return new ASN1ObjectIdentifier(oid);
	}

	private ASN1Set toSet(Object object) {
    	if (object instanceof FailInfo) {
    		return toSet((FailInfo) object);
    	} else if (object instanceof PkiStatus) {
    		return toSet((PkiStatus) object);
    	} else  if (object instanceof Nonce) {
    		return toSet((Nonce) object);
    	} else if (object instanceof TransactionId) {
    		return toSet((TransactionId) object);
    	} else if (object instanceof MessageType) {
    		return toSet((MessageType) object);
    	} else if (object instanceof ASN1ObjectIdentifier) {
    		return new DERSet((ASN1ObjectIdentifier) object);
    	}
        throw new IllegalArgumentException("Unexpected object");
    }
    
    private ASN1Set toSet(FailInfo failInfo) {
        return new DERSet(new DERPrintableString(Integer.toString(failInfo.getValue())));
    }

    private ASN1Set toSet(PkiStatus pkiStatus) {
        return new DERSet(new DERPrintableString(Integer.toString(pkiStatus.getValue())));
    }
    
    private ASN1Set toSet(Nonce nonce) {
        return new DERSet(new DEROctetString(nonce.getBytes()));
    }

    private ASN1Set toSet(TransactionId transId) {
        return new DERSet(new DERPrintableString(transId.toString()));
    }

    private ASN1Set toSet(MessageType messageType) {
        return new DERSet(new DERPrintableString(Integer.toString(messageType.getValue())));
    }
}
