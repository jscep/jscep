package org.jscep.transport.response;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Collections;
import java.util.EnumSet;

import net.jcip.annotations.Immutable;

/**
 * This class represents a set of capabilities for a particular SCEP server.
 */
@Immutable
public final class Capabilities {
    private final EnumSet<Capability> capabilities;

    /**
     * Constructs a new instance of this class with the specified capabilities.
     * 
     * @param capabilities
     *            the capabilities.
     */
    public Capabilities(Capability... capabilities) {
	this.capabilities = EnumSet.noneOf(Capability.class);
	Collections.addAll(this.capabilities, capabilities);
    }

    /**
     * Returns <code>true</code> if the server supports the provided Capability,
     * <code>false</code> otherwise.
     * 
     * @param capability
     *            the capability to test for.
     * @return <code>true</code> if the server supports the provided Capability,
     *         <code>false</code> otherwise.
     */
    public boolean contains(Capability capability) {
	return capabilities.contains(capability);
    }

    /**
     * Returns <tt>true</tt> if POST is supported, <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if POST is supported, <tt>false</tt> otherwise.
     */
    public boolean isPostSupported() {
	return capabilities.contains(Capability.POST_PKI_OPERATION);
    }

    /**
     * Returns <tt>true</tt> if retrieval of the next CA is supported,
     * <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if retrieval of the next CA is supported,
     *         <tt>false</tt> otherwise.
     */
    public boolean isRolloverSupported() {
	return capabilities.contains(Capability.GET_NEXT_CA_CERT);
    }

    /**
     * Returns <tt>true</tt> if certificate renewal is supported, <tt>false</tt>
     * otherwise.
     * 
     * @return <tt>true</tt> if certificate renewal is supported, <tt>false</tt>
     *         otherwise.
     */
    public boolean isRenewalSupported() {
	return capabilities.contains(Capability.RENEWAL);
    }

    /**
     * Returns the strongest cipher algorithm supported by the server and
     * client.
     * <p/>
     * The algorithms are ordered thus:
     * <ol>
     * <li>DESede ("Triple DES")</li>
     * <li>DES</li>
     * </ol>
     * 
     * @return the strongest cipher algorithm supported by the server and
     *         client.
     */
    public String getStrongestCipher() {
	final String cipher;
	if (cipherExists("DESede")
		&& capabilities.contains(Capability.TRIPLE_DES)) {
	    cipher = "DESede";
	} else {
	    cipher = "DES";
	}

	return cipher;
    }

    private boolean cipherExists(String algorithm) {
	return algorithmExists("Cipher", algorithm);
    }

    private boolean algorithmExists(String serviceType, String algorithm) {
	for (Provider provider : Security.getProviders()) {
	    for (Service service : provider.getServices()) {
		if (service.getType().equals(serviceType)
			&& service.getAlgorithm().equals(algorithm)) {
		    return true;
		}
	    }
	}

	return false;
    }

    /**
     * Returns the strongest message digest algorithm supported by the server
     * and client.
     * <p/>
     * The algorithms are ordered thus:
     * <ol>
     * <li>SHA-512</li>
     * <li>SHA-256</li>
     * <li>SHA-1</li>
     * <li>MD5</li>
     * </ol>
     * 
     * @return the strongest message digest algorithm supported by the server
     *         and client.
     */
    public String getStrongestMessageDigest() {
	final String digest;
	if (digestExists("SHA-512")
		&& capabilities.contains(Capability.SHA_512)) {
	    digest = "SHA-512";
	} else if (digestExists("SHA-256")
		&& capabilities.contains(Capability.SHA_256)) {
	    digest = "SHA-256";
	} else if (digestExists("SHA-1")
		&& capabilities.contains(Capability.SHA_1)) {
	    digest = "SHA-1";
	} else {
	    digest = "MD5";
	}

	return digest;
    }

    private boolean digestExists(String digest) {
	return algorithmExists("MessageDigest", digest);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
	return capabilities.toString();
    }
}
