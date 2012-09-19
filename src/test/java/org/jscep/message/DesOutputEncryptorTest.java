package org.jscep.message;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.OutputEncryptor;
import org.junit.Before;
import org.junit.Test;

public class DesOutputEncryptorTest {
	private OutputEncryptor encryptor;
	
	@Before
	public void setUp() {
		encryptor = new DesOutputEncryptor();
	}
	
	@Test
	public void getKeyShouldReturnSameKey() {
		assertSame(encryptor.getKey().getRepresentation(), encryptor.getKey().getRepresentation());
	}
	
	@Test
	public void getKeyShouldReturnKey() {
		assertThat(encryptor.getKey().getRepresentation(), instanceOf(Key.class));
	}
	
	@Test
	public void getAlgorithmIdentifierShouldReturnDes() {
		assertEquals(new ASN1ObjectIdentifier("1.3.14.3.2.7"), encryptor.getAlgorithmIdentifier().getAlgorithm());
	}
	
	@Test
	public void getOutputStreamShouldEncrypt() throws IOException {
		byte[] bytes = "cafebabe".getBytes("UTF-8");
		
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		OutputStream encOut = encryptor.getOutputStream(bOut);
		encOut.write(bytes);
		
		assertFalse(Arrays.equals(bytes, bOut.toByteArray()));
	}
}
