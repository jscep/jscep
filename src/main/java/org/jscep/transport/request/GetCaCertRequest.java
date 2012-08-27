package org.jscep.transport.request;

/**
 * This class represents a <code>GetCACert</code> request.
 */
public final class GetCaCertRequest extends Request {
    private final String profile;

    /**
     * Creates a new <tt>GetCaCertRequest</tt> with the given CA profile.
     * 
     * @param profile
     *            the CA profile to use.
     */
    public GetCaCertRequest(String profile) {
	super(Operation.GET_CA_CERT);

	this.profile = profile;
    }

    /**
     * Creates a new <tt>GetCaCertRequest</tt> without a CA profile.
     */
    public GetCaCertRequest() {
	this(null);
    }

    /**
     * {@inheritDoc}
     */
    public String getMessage() {
	if (profile == null) {
	    return "";
	}
	return profile;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
	if (profile != null) {
	    return "GetCACert(" + profile + ")";
	} else {
	    return "GetCACert";
	}
    }
}
