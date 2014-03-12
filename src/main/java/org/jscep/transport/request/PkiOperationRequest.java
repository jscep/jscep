package org.jscep.transport.request;

import java.io.IOException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cms.CMSSignedData;

/**
 * The <tt>PkiOperationRequest</tt> class may represent a <tt>PKCSReq</tt>,
 * <tt>GetCertInitial</tt>, <tt>GetCert</tt> and <tt>GetCRL</tt> request.
 */
public final class PkiOperationRequest extends Request {
    private final CMSSignedData msgData;

    /**
     * Creates a new <tt>PkiOperationRequest</tt> for the given
     * <tt>signedData</tt>
     * 
     * @param msgData
     *            the pkiMessage to use.
     */
    public PkiOperationRequest(final CMSSignedData msgData) {
        super(Operation.PKI_OPERATION);

        this.msgData = msgData;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getMessage() {
        try {
            return new String(Base64.encodeBase64(msgData.getEncoded(), false), "UTF-8");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return msgData.toString();
    }
}
