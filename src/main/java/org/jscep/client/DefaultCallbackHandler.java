package org.jscep.client;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.client.verification.CertificateVerifier;

/**
 * Class that handles a CertificateVerificationCallback.
 */
public final class DefaultCallbackHandler implements CallbackHandler {
    /**
     * The verifier.
     */
    private final CertificateVerifier verifier;
    private final Map<String, String> passwords;

    /**
     * Default callback handler that delegates verification to a verifier.
     * 
     * @param verifier
     *            the verifier to use.
     */
    public DefaultCallbackHandler(final CertificateVerifier verifier, final Map<String, String> passwords) {
        this.verifier = verifier;
        this.passwords = passwords;
    }

    /**
     * Default callback handler that delegates verification to a verifier.
     *
     * @param verifier
     *            the verifier to use.
     */
    public DefaultCallbackHandler(final CertificateVerifier verifier) {
        this(verifier, new HashMap<>());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void handle(final Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof CertificateVerificationCallback) {
                verify(CertificateVerificationCallback.class.cast(callback));
            } else if (callback instanceof PasswordCallback) {
                handle(PasswordCallback.class.cast(callback));
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    /**
     * Verify the callback certificate.
     * 
     * @param callback
     *            the callback to verify.
     */
    private void verify(final CertificateVerificationCallback callback) {
        callback.setVerified(verifier.verify(callback.getCertificate()));
    }

    /**
     * Provide specific password based on profile name in callback's prompt.
     *
     * @param callback the callback to handle
     */
    private void handle(final PasswordCallback callback) {
        if (passwords == null) {
            return;
        }
        if (passwords.size() == 1) {
            // we have only one password, just return it
            String password = passwords.get(passwords.keySet().iterator().next());
            if (password != null) {
                callback.setPassword(password.toCharArray());
            }
        } else {
            // if we have many passwords, return one selected by profile name included in prompt
            for (String key : passwords.keySet()) {
                if (callback.getPrompt().contains(key)) {
                    callback.setPassword(passwords.get(key).toCharArray());
                }
            }
        }
    }
}
