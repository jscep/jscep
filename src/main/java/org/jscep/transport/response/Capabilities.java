package org.jscep.transport.response;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
	private final EnumSet<Capability> caps;

	/**
	 * Constructs a new instance of this class with the specified capabilities.
	 * 
	 * @param capabilities
	 *            the capabilities.
	 */
	public Capabilities(Capability... capabilities) {
		this.caps = EnumSet.noneOf(Capability.class);
		Collections.addAll(this.caps, capabilities);
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
		return caps.contains(capability);
	}

	/**
	 * Returns <tt>true</tt> if POST is supported, <tt>false</tt> otherwise.
	 * 
	 * @return <tt>true</tt> if POST is supported, <tt>false</tt> otherwise.
	 */
	public boolean isPostSupported() {
		return caps.contains(Capability.POST_PKI_OPERATION);
	}

	/**
	 * Returns <tt>true</tt> if retrieval of the next CA is supported,
	 * <tt>false</tt> otherwise.
	 * 
	 * @return <tt>true</tt> if retrieval of the next CA is supported,
	 *         <tt>false</tt> otherwise.
	 */
	public boolean isRolloverSupported() {
		return caps.contains(Capability.GET_NEXT_CA_CERT);
	}

	/**
	 * Returns <tt>true</tt> if certificate renewal is supported, <tt>false</tt>
	 * otherwise.
	 * 
	 * @return <tt>true</tt> if certificate renewal is supported, <tt>false</tt>
	 *         otherwise.
	 */
	public boolean isRenewalSupported() {
		return caps.contains(Capability.RENEWAL);
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
		if (cipherExists("DESede") && caps.contains(Capability.TRIPLE_DES)) {
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
	 * If none of the above algorithms are supported, this method returns null.
	 * 
	 * @return the strongest message digest algorithm supported by the server
	 *         and client.
	 */
	public MessageDigest getStrongestMessageDigest() {
		if (digestExists("SHA-512") && caps.contains(Capability.SHA_512)) {
			return getDigest("SHA-512");
		} else if (digestExists("SHA-256") && caps.contains(Capability.SHA_256)) {
			return getDigest("SHA-256");
		} else if (digestExists("SHA-1") && caps.contains(Capability.SHA_1)) {
			return getDigest("SHA-1");
		} else if (digestExists("MD5")) {
			return getDigest("MD5");
		}
		return null;
	}

	public String getStrongestSignatureAlgorithm() {
		if (sigExists("SHA512") && caps.contains(Capability.SHA_512)) {
			return "SHA512withRSA";
		} else if (sigExists("SHA256") && caps.contains(Capability.SHA_256)) {
			return "SHA256withRSA";
		} else if (sigExists("SHA1") && caps.contains(Capability.SHA_1)) {
			return "SHA1withRSA";
		} else if (sigExists("MD5")) {
			return "MD5withRSA";
		}
		return null;
	}

	private boolean sigExists(String sig) {
		return algorithmExists("Signature", sig + "withRSA")
				&& digestExists(sig);
	}

	private boolean digestExists(String digest) {
		return algorithmExists("MessageDigest", digest);
	}

	private MessageDigest getDigest(String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return caps.toString();
	}
}
