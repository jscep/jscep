/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.gui;

import java.awt.HeadlessException;
import java.io.IOException;
import java.net.MalformedURLException;
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

import org.jscep.FingerprintVerificationCallback;
import org.jscep.client.Client;
import org.jscep.transaction.Transaction;
import org.jscep.util.HexUtil;
import org.jscep.x509.X509Util;


public class Main extends JFrame {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public Main() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		X500Principal subject = new X500Principal("CN=example.org");
		X509Certificate identity = X509Util.createEphemeralCertificate(subject, keyPair);
		Client.Builder builder = new Client.Builder();
		builder.url(getURL());
		builder.identity(identity, keyPair);
		builder.callbackHandler(new Handler());
		Client client = builder.build();
		Transaction transaction = client.createTransaction();
		transaction.enrollCertificate(identity, keyPair, "INBOUND_TLSuscl99".toCharArray());
	}
	
	public URL getURL() throws HeadlessException, MalformedURLException {
		return new URL(JOptionPane.showInputDialog("SCEP URL"));
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
			new Main();
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
