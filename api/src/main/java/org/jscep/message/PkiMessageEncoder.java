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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;

public class PkiMessageEncoder {
	private final PrivateKey senderKey;
	private final X509Certificate senderCert;
	private final PkcsPkiEnvelopeEncoder encoder;
	
	public PkiMessageEncoder(PrivateKey priKey, X509Certificate sender, PkcsPkiEnvelopeEncoder encoder) {
		this.senderKey = priKey;
		this.senderCert = sender;
		this.encoder = encoder;
	}
	
	public CMSSignedData encode(PkiMessage<? extends ASN1Encodable> message) throws IOException {
		CMSEnvelopedData ed = encoder.encode(message.getMessageData());
		CMSProcessable signable = new CMSProcessableByteArray(ed.getEncoded());
		CMSSignedDataGenerator sdGenerator = new CMSSignedDataGenerator();
		
		Hashtable<DERObjectIdentifier, Attribute> table = new Hashtable<DERObjectIdentifier, Attribute>();
		for (Attribute attr : message.getAttributes()) {
			table.put(attr.getAttrType(), attr);
		}
		AttributeTable signedAttrs = new AttributeTable(table);
		Collection<X509Certificate> certColl = Collections.singleton(senderCert);
		CertStore store;
		try {
			store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certColl));
		} catch (Exception e) {
			throw new IOException(e);
		}
		
		sdGenerator.addSigner(senderKey, senderCert, CMSSignedGenerator.DIGEST_SHA1, signedAttrs, null);
		try {
			sdGenerator.addCertificatesAndCRLs(store);
		} catch (Exception e) {
			throw new IOException(e);
		}
		
		try {
			return sdGenerator.generate(signable, true, (String) null);
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
}
