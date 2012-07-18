/*
 * Copyright (c) 2009-2010 David Grant
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
package org.jscep.util;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.md5WithRSAEncryption;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.sha1WithRSAEncryption;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.sha256WithRSAEncryption;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.sha512WithRSAEncryption;

import java.security.AlgorithmParameters;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.smime.SMIMECapabilities;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceAlgorithmIdentifierConverter;

/**
 * This class provides a utility to lookup a friendly name for an algorithm
 * given a particular OID or AlgorithmIdentifier.
 * <p/>
 * The internal dictionary is by no means comprehensive, and new algorithms are
 * generally as and when they are required by changes to the SCEP specification.
 * 
 * @author David Grant
 * @link 
 *       http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames
 *       .html
 */
public final class AlgorithmDictionary {
    private static final Map<DERObjectIdentifier, String> CONTENTS = new HashMap<DERObjectIdentifier, String>();

    static {
        // Asymmetric Ciphers
        CONTENTS.put(rsaEncryption, "RSA");
        // Digital Signatures
        CONTENTS.put(sha1WithRSAEncryption, "SHA1withRSA");
        CONTENTS.put(md5WithRSAEncryption, "md5withRSA");
        CONTENTS.put(sha256WithRSAEncryption, "sha256withRSA");
        CONTENTS.put(sha512WithRSAEncryption, "sha512withRSA");
        // Symmetric Ciphers
        CONTENTS.put(SMIMECapabilities.dES_CBC, "DES/CBC/PKCS5Padding"); // DES
        CONTENTS.put(SMIMECapabilities.dES_EDE3_CBC, "DESede/CBC/PKCS5Padding"); // DESEDE
        // Message Digests
        CONTENTS.put(X509ObjectIdentifiers.id_SHA1, "SHA");
        CONTENTS.put(new DERObjectIdentifier("1.2.840.113549.2.5"), "MD5");
        CONTENTS.put(new DERObjectIdentifier("2.16.840.1.101.3.4.2.1"),
                "SHA-256");
        CONTENTS.put(new DERObjectIdentifier("2.16.840.1.101.3.4.2.3"),
                "SHA-512");
    }

    private AlgorithmDictionary() {
        // This constructor will never be invoked.
    }

    /**
     * Returns the cipher part of the provided transformation.
     * 
     * @param transformation
     *            the transformation, e.g. "DES/CBC/PKCS5Padding"
     * @return the cipher, e.g. "DES"
     */
    public static String fromTransformation(String transformation) {
        return transformation.split("/")[0];
    }

    /**
     * Returns the name of the given algorithm.
     * 
     * @param alg
     *            the algorithm to look up.
     * @return the algorithm name.
     */
    public static String lookup(AlgorithmIdentifier alg) {
        return CONTENTS.get(alg.getAlgorithm());
    }
}
