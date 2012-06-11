package org.jscep.client;

import org.jscep.CertificateVerificationCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

public class NoSecurityCallbackHandler implements CallbackHandler {
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof CertificateVerificationCallback) {
                ((CertificateVerificationCallback) callback).setVerified(true);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }
}
