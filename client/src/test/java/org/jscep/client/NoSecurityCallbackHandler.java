package org.jscep.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.FingerprintVerificationCallback;

public class NoSecurityCallbackHandler implements CallbackHandler {
	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof FingerprintVerificationCallback) {
				FingerprintVerificationCallback callback = (FingerprintVerificationCallback) callbacks[i];
				callback.setVerified(true);
			} else {
				throw new UnsupportedCallbackException(callbacks[i]);
			}
		}
	}
}
