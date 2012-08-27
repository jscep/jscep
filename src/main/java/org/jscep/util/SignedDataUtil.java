package org.jscep.util;

import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * This class contains utility methods for manipulating SignedData objects.
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
    public static boolean isSignedBy(CMSSignedData sd, X509Certificate signer) {
	SignerInformationStore store = sd.getSignerInfos();
	SignerInformation signerInfo = store.get(new JcaSignerId(signer));
	if (signerInfo == null) {
	    return false;
	}
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
	    digestProvider = new JcaDigestCalculatorProviderBuilder().build();
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
}
