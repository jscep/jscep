package org.jscep.example;

import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.FingerprintVerificationCallback;
import org.jscep.client.Client;

public class SimpleExample {
	public static void main(String[] args) throws Exception {
		final KeyStore store = KeyStore.getInstance("JKS");
		store.load(new FileInputStream("src/main/resources/example.jks"), "jscep.org".toCharArray());
		
		final URL url = new URL("http://jscep.org/scep/pkiclient.exe");
		final X509Certificate identity = (X509Certificate) store.getCertificate("jscep");
		final PrivateKey privKey = (PrivateKey) store.getKey("jscep", "jscep.org".toCharArray());
		final CallbackHandler cbh = new ConsoleCallbackHandler();
		
		final Client scepClient = new Client(url, identity, privKey, cbh);
		scepClient.getCaCertificate();
	}
	
	private static class ConsoleCallbackHandler implements CallbackHandler {
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof FingerprintVerificationCallback) {
					final FingerprintVerificationCallback callback = (FingerprintVerificationCallback) callbacks[i];
					byte[] fingerprint;
					try {
						fingerprint = callback.getFingerprint("MD5");
					} catch (Exception e) {
						continue;
					}
					final Console console = System.console();
					if (console == null) {
						continue;
					}
					final PrintWriter writer = console.writer();
					writer.write("Is this the MD5 hash of your CA's certificate?\n");
					writer.write(new String(fingerprint) + "\n");
					writer.write("[yes/no]: ");
					writer.flush();
					final String reply = console.readLine();
					if (reply.equals("yes")) {
						callback.setVerified(true);
					}
				} else {
					throw new UnsupportedCallbackException(callbacks[i]);
				}
			}
		}
		
	}
}
