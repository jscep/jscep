package com.google.code.jscep.gui;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

import com.google.code.jscep.FingerprintVerificationCallback;
import com.google.code.jscep.client.Client;
import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.util.HexUtil;
import com.google.code.jscep.x509.X509Util;

public class Main extends JFrame {
	public Main() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		X500Principal subject = new X500Principal("CN=example.org");
		X509Certificate identity = X509Util.createEphemeralCertificate(subject, keyPair);
		Client.Builder builder = new Client.Builder();
		builder.url(new URL("https://engtest66-2.eu.ubiquity.net/ejbca/publicweb/apply/scep/pkiclient.exe"));
		builder.identity(identity, keyPair);
		builder.callbackHandler(new Handler());
		Client client = builder.build();
		Transaction transaction = client.createTransaction();
		transaction.enrollCertificate(identity, keyPair, "INBOUND_TLSuscl99".toCharArray());
		System.out.println(transaction.getCertStore());
	}
	
	public static void main(String[] args) throws Exception {
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, new TrustManager[] {new X509TrustManager() {
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			}

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		}}, null);
		HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
		
		try {
			Main main = new Main();
//			main.setTitle("jSCEP GUI");
//			main.setVisible(true);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private class Handler implements CallbackHandler {
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (Callback callback : callbacks) {
				if (callback instanceof FingerprintVerificationCallback) {
					FingerprintVerificationCallback fvcCallback = (FingerprintVerificationCallback) callback;
					String hash = HexUtil.toHexString(fvcCallback.getFingerprint());
					String prompt = "Is this the " + fvcCallback.getAlgorithm() + " hash of your CA certificate?\n\n" + hash;
					int n = JOptionPane.showConfirmDialog(null, prompt, "Confirmation", JOptionPane.YES_NO_OPTION);
					if (n == JOptionPane.NO_OPTION) {
						fvcCallback.setVerified(false);
					} else {
						fvcCallback.setVerified(true);
					}
				}
			}
		}
		
	}
}
