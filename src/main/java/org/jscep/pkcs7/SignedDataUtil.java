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
package org.jscep.pkcs7;

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * This class contains utility methods for manipulating SignedData objects.
 * 
 * @author David Grant
 */
public final class SignedDataUtil {
    /**
     * Private constructor to prevent instantiation.
     */
    private SignedDataUtil() {
    }

    /**
     * Checks if the provided signedData was signed by the entity represented by
     * the provided certificate.
     * 
     * @param sd
     *            the signedData to verify.
     * @param signer
     *            the signing entity.
     * @return <code>true</code> if the signedData was signed by the entity,
     *         <code>false</code> otherwise.
     */
    @SuppressWarnings("unchecked")
    public static boolean isSignedBy(CMSSignedData sd, X509Certificate signer) {
        Collection<SignerInformation> signerInfos = sd.getSignerInfos()
                .getSigners();
        for (SignerInformation signerInfo : signerInfos) {
            CMSSignatureAlgorithmNameGenerator sigNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
            SignatureAlgorithmIdentifierFinder sigAlgorithmFinder = new DefaultSignatureAlgorithmIdentifierFinder();
            ContentVerifierProvider verifierProvider;
            try {
                verifierProvider = new JcaContentVerifierProviderBuilder()
                        .build(signer);
            } catch (OperatorCreationException e) {
                throw new RuntimeException(e);
            }
            DigestCalculatorProvider digestProvider;
            try {
                digestProvider = new JcaDigestCalculatorProviderBuilder()
                        .build();
            } catch (OperatorCreationException e1) {
                throw new RuntimeException(e1);
            }
            SignerInformationVerifier verifier = new SignerInformationVerifier(
                    sigNameGenerator, sigAlgorithmFinder, verifierProvider,
                    digestProvider);
            try {
                return signerInfo.verify(verifier);
            } catch (CMSException e) {
                return false;
            }
        }

        return false;
    }
}
