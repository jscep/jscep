package org.jscep.message;

import java.io.IOException;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;

public class DesOutputEncryptor implements OutputEncryptor {
	private static final String CIPHER = "DES";
	private static final String TRANSFORMATION = "DES/CBC/PKCS5Padding";
	private static final ASN1ObjectIdentifier DES_OID = new ASN1ObjectIdentifier("1.3.14.3.2.7");
	private final SecretKey key;
	private final AlgorithmIdentifier algId;
	private final Cipher cipher;
	
	public DesOutputEncryptor() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER);
			key = keyGen.generateKey();
			SecureRandom rnd = new SecureRandom();
			byte[] iv = new byte[8];
			rnd.nextBytes(iv);
			IvParameterSpec paramSpec = new IvParameterSpec(iv);
			
			cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
			AlgorithmParameters params = AlgorithmParameters.getInstance(CIPHER);
			params.init(paramSpec);
			
			ASN1Primitive sParams = ASN1Primitive.fromByteArray(params.getEncoded("ASN.1"));
			algId = new AlgorithmIdentifier(DES_OID, sParams);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public AlgorithmIdentifier getAlgorithmIdentifier() {
		return algId;
	}

	public OutputStream getOutputStream(OutputStream encOut) {
		return new CipherOutputStream(encOut, cipher);
	}

	public GenericKey getKey() {
		return new GenericKey(key);
	}

}
