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
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
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
        CMSProcessable signable;

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
        	} else {
        		ed = encoder.encode(((ASN1Encodable) message.getMessageData()).getEncoded());
        	}
            signable = new CMSProcessableByteArray(ed);
        } else {
            signable = null;
        }

        Hashtable<DERObjectIdentifier, Attribute> table = new Hashtable<DERObjectIdentifier, Attribute>();
        for (Map.Entry<String, Object> entry : message.getAttributes().entrySet()) {
        	DERObjectIdentifier oid = toOid(entry.getKey());
        	table.put(oid, new Attribute(oid, toSet(entry.getValue())));
        }
        AttributeTable signedAttrs = new AttributeTable(table);
        Collection<X509Certificate> certColl = Collections.singleton(senderCert);
        CertStore store;
        try {
            store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certColl));
        } catch (Exception e) {
            throw new IOException(e);
        }

        CMSSignedDataGenerator sdGenerator = new CMSSignedDataGenerator();
        LOGGER.debug("Signing message using key belonging to '{}'", senderCert.getSubjectDN());
        sdGenerator.addSigner(senderKey, senderCert, CMSSignedGenerator.DIGEST_SHA1, signedAttrs, null);
        try {
            sdGenerator.addCertificatesAndCRLs(store);
        } catch (Exception e) {
            throw new IOException(e);
        }

        try {
            LOGGER.debug("Signing {} content", signable);
            CMSSignedData sd = sdGenerator.generate(signable, true, (String) null);
            LOGGER.debug("Encoded to: {}", sd.getEncoded());
            return sd.getEncoded();
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
    
    private DERObjectIdentifier toOid(String oid) {
		return new DERObjectIdentifier(oid);
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
        return new DERSet(new DERPrintableString(transId.getBytes()));
    }

    private ASN1Set toSet(MessageType messageType) {
        return new DERSet(new DERPrintableString(Integer.toString(messageType.getValue())));
    }
}
