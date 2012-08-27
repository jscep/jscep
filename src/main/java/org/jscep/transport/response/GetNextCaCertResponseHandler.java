package org.jscep.transport.response;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.util.CertStoreUtils;
import org.jscep.util.SignedDataUtil;

/**
 * This class handles responses to <code>GetNextCACert</code> requests.
 */
public class GetNextCaCertResponseHandler implements
	ScepResponseHandler<CertStore> {
    private static final String NEXT_CA_CERT = "application/x-x509-next-ca-cert";
    private final X509Certificate signer;

    /**
     * Creates a new <tt>GetNextCaCertResponseHandler</tt> using the provided certificate.
     * 
     * @param signer the signer of the <tt>signedData</tt> response.
     */
    public GetNextCaCertResponseHandler(X509Certificate signer) {
	this.signer = signer;
    }

    /**
     * {@inheritDoc}
     */
    public CertStore getResponse(byte[] content, String mimeType)
	    throws ContentException {
	if (mimeType.startsWith(NEXT_CA_CERT)) {
	    // http://tools.ietf.org/html/draft-nourse-scep-20#section-4.6.1

	    // The response consists of a SignedData PKCS#7 [RFC2315],
	    // signed by the current CA (or RA) signing key.
	    try {
		CMSSignedData cmsMessageData = new CMSSignedData(content);
		ContentInfo cmsContentInfo = ContentInfo
			.getInstance(cmsMessageData.getEncoded());

		final CMSSignedData sd = new CMSSignedData(cmsContentInfo);
		if (!SignedDataUtil.isSignedBy(sd, signer)) {
		    throw new InvalidContentException("Invalid Signer");
		}
		// The content of the SignedData PKCS#7 [RFC2315] is a
		// degenerate
		// certificates-only Signed-data (Section 3.3) message
		// containing the
		// new CA certificate and any new RA certificates, as defined in
		// Section 5.2.1.1.2, to be used when the current CA certificate
		// expires.
		return CertStoreUtils.fromSignedData(sd);
	    } catch (IOException e) {
		throw new InvalidContentTypeException(e);
	    } catch (CMSException e) {
		throw new InvalidContentTypeException(e);
	    }
	} else {
	    throw new InvalidContentTypeException(mimeType, NEXT_CA_CERT);
	}
    }
}
