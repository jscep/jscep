package com.google.code.jscep.util;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.junit.Test;

/**
 * This is a sanity test for the algorithms recognised by the algorithm
 * dictionary.
 * 
 * @author David Grant
 */
public class AlgorithmDictionaryTest {
	@Test
	public void testAlgorithmParameters() throws Exception {
		AlgorithmParameters.getInstance("DES");
		AlgorithmParameters.getInstance("DESede");
	}
	
	@Test
	public void testCiphers() throws Exception {
		Cipher.getInstance("DES/CBC/PKCS5Padding");
		Cipher.getInstance("DESede/CBC/PKCS5Padding");
	}
	
	@Test
	public void testKeyFactories() throws Exception {
		KeyFactory.getInstance("RSA");
	}
	
	@Test
	public void testKeyPairGenerators() throws Exception {
		KeyPairGenerator.getInstance("RSA");
	}
	
	@Test
	public void testKeyGenerators() throws Exception {
		KeyGenerator.getInstance("DES");
		KeyGenerator.getInstance("DESede");
	}

	@Test
	public void testMessageDigests() throws Exception {
		MessageDigest.getInstance("MD5");
		MessageDigest.getInstance("SHA-1");
		MessageDigest.getInstance("SHA-256");
		MessageDigest.getInstance("SHA-512");
	}
	
	@Test
	public void testSignatures() throws Exception {
		Signature.getInstance("MD5withRSA");
		Signature.getInstance("SHA1withRSA");
		Signature.getInstance("SHA256withRSA");
		Signature.getInstance("SHA512withRSA");
	}
}
