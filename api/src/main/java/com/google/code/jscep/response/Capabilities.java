package com.google.code.jscep.response;

import java.security.Security;
import java.util.EnumSet;
import java.util.Set;

/**
 * This class represents a set of capabilities for a particular
 * SCEP server.
 */
public class Capabilities {
	private EnumSet<Capability> capabilities;

	/**
	 * Constructs a new instance of this class with the specified
	 * capabilities.
	 * 
	 * @param capabilities the capabilities.
	 */
	public Capabilities(Capability... capabilities) {
		this.capabilities = EnumSet.noneOf(Capability.class);

		for (Capability capability : capabilities) {
			this.capabilities.add(capability);
		}
	}
	
	/**
	 * Add the specified capability to this capabilities set.
	 * 
	 * @param capability the capability to add.
	 */
	public void add(Capability capability) {
		capabilities.add(capability);
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
	 * Returns <tt>true</tt> if retrieval of the next CA is supported, <tt>false</tt> otherwise.
	 *  
	 * @return <tt>true</tt> if retrieval of the next CA is supported, <tt>false</tt> otherwise.
	 */
	public boolean isNextCASupported() {
		return capabilities.contains(Capability.GET_NEXT_CA_CERT);
	}
	
	/**
	 * Returns <tt>true</tt> if certificate renewal is supported, <tt>false</tt> otherwise.
	 *  
	 * @return <tt>true</tt> if certificate renewal is supported, <tt>false</tt> otherwise.
	 */
	public boolean isRenewalSupported() {
		return capabilities.contains(Capability.RENEWAL);
	}
	
	/**
	 * Returns the strongest cipher algorithm supported by the server and client.
	 * <p>
	 * The algorithms are ordered thus:
	 * <ol>
	 *     <li>Triple DES</li>
	 *     <li>DES</li>
	 * </ol>
	 * 
	 * @return the strongest cipher algorithm supported by the server and client.
	 */
	public String getStrongestCipher() {
		final Set<String> ciphers = Security.getAlgorithms("Cipher");
		
		if (ciphers.contains("DESEDE") && capabilities.contains(Capability.TRIPLE_DES)) {
			return "DESEDE";
		} else {
			return "DES";
		}
	}
	
	/**
	 * Returns the strongest message digest algorithm supported by the server and client.
	 * <p>
	 * The algorithms are ordered thus:
	 * <ol>
	 *     <li>SHA-512</li>
	 *     <li>SHA-256</li>
	 *     <li>SHA-1</li>
	 *     <li>MD5</li>
	 * </ol>
	 * 
	 * @return the strongest message digest algorithm supported by the server and client.
	 */
	public String getStrongestMessageDigest() {
		final Set<String> digests = Security.getAlgorithms("MessageDigest");
		
		if (digests.contains("SHA-512") && capabilities.contains(Capability.SHA_512)) {
			return "SHA-512";
		} else if (digests.contains("SHA-256") && capabilities.contains(Capability.SHA_256)) {
			return "SHA-256";
		} else if (digests.contains("SHA") && capabilities.contains(Capability.SHA_1)) {
			return "SHA";
		} else {
			return "MD5";
		}
	}
}
