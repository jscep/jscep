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
package org.jscep.x509;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * This is a utility class for performing various operations pertaining to X.509
 * certificates.
 * 
 * @author David Grant
 */
public final class X509Util {
    private X509Util() {
        // This constructor will never be invoked.
    }

    /**
     * Converts a Java SE X500Principal to a Bouncy Castle X509Name.
     * 
     * @param principal
     *            the principal to convert.
     * @return the converted name.
     */
    public static X500Name toX509Name(X500Principal principal) {
        byte[] bytes = principal.getEncoded();
        return X500Name.getInstance(bytes);
    }
    
    public static PublicKey getPublicKey(PKCS10CertificationRequest csr)
            throws InvalidKeySpecException, IOException {
        SubjectPublicKeyInfo pubKeyInfo = csr.getSubjectPublicKeyInfo();
        RSAKeyParameters keyParams = (RSAKeyParameters) PublicKeyFactory
                .createKey(pubKeyInfo);
        KeySpec keySpec = new RSAPublicKeySpec(keyParams.getModulus(),
                keyParams.getExponent());

        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return kf.generatePublic(keySpec);
    }
}
