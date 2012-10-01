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

/**
 * {@link OutputEncrypter} that uses a DES cipher.
 */
public final class DesOutputEncryptor implements OutputEncryptor {
    /**
     * The JCA cipher name.
     */
    private static final String CIPHER = "DES";
    /**
     * The JCA cipher transformation name.
     */
    private static final String TRANSFORMATION = "DES/CBC/PKCS5Padding";
    /**
     * The OID corresponding to the transformation.
     */
    private static final ASN1ObjectIdentifier DES_OID = new ASN1ObjectIdentifier(
            "1.3.14.3.2.7");
    /**
     * The generated key.
     */
    private final SecretKey key;
    /**
     * The algorithm identifier for the transformation.
     */
    private final AlgorithmIdentifier algId;
    /**
     * The generated cipher.
     */
    private final Cipher cipher;

    /**
     * Creates a new {@code OutputEncryptor}.
     */
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
            AlgorithmParameters params = AlgorithmParameters
                    .getInstance(CIPHER);
            params.init(paramSpec);

            ASN1Primitive sParams = ASN1Primitive.fromByteArray(params
                    .getEncoded("ASN.1"));
            algId = new AlgorithmIdentifier(DES_OID, sParams);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algId;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OutputStream getOutputStream(final OutputStream encOut) {
        return new CipherOutputStream(encOut, cipher);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public GenericKey getKey() {
        return new GenericKey(key);
    }

}
