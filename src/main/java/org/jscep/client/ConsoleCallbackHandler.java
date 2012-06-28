package org.jscep.client;

import static java.security.Security.getAlgorithms;
import static org.jscep.util.HexUtil.toHexString;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Scanner;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.CertificateVerificationCallback;

/**
 * This class is a console-focused implementation of CallbackHandler.
 * <p>
 * Implementors should use this if they require interactive certificate
 * verification in a command line application.
 */
public class ConsoleCallbackHandler implements CallbackHandler {
    /**
     * {@inheritDoc}
     */
    public final void handle(final Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {
        for (final Callback callback : callbacks) {
            if (callback instanceof CertificateVerificationCallback) {
                try {
                    final CertificateVerificationCallback cert = (CertificateVerificationCallback) callback;
                    cert.setVerified(verify(cert.getCertificate()));
                } catch (final GeneralSecurityException e) {
                    final IOException ioe = new IOException();
                    ioe.initCause(e);

                    throw ioe;
                }
            }
        }
    }

    /**
     * Use the system console to prompt the user with each available hash.
     * 
     * @param cert the certificate to verify
     * @return <tt>true</tt> if the certificate is verified, <tt>false</tt>
     *         otherwise.
     * @throws GeneralSecurityException if any security error occurs
     */
    private boolean verify(final X509Certificate cert)
            throws GeneralSecurityException {
        final List<String> algs = new ArrayList<String>(
                getAlgorithms(MessageDigest.class.getSimpleName()));
        Collections.sort(algs);
        int max = 0;
        for (final String alg : algs) {
            if (alg.length() > max) {
                max = alg.length();
            }
        }
        for (final String alg : algs) {
            final MessageDigest digest = MessageDigest.getInstance(alg);
            final byte[] hash = digest.digest(cert.getEncoded());
            System.out.format("%" + max + "s: %s%n", alg, toHexString(hash));
        }
        final Scanner scanner = new Scanner(System.in, Charset.defaultCharset()
                .name()).useDelimiter(String.format("%n"));
        while (true) {
            System.out.format("%nAccept? (Y/N): [N]%n");
            try {
                final String answer = scanner.next();
                System.out.println(answer);
                if (answer.equals("Y")) {
                    return true;
                } else if (answer.equals("N")) {
                    return false;
                }
            } catch (final NoSuchElementException e) {
                return false;
            }
        }
    }
}
