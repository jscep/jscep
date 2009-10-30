package com.google.code.jscep.transport;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;

import com.google.code.jscep.request.Request;

/**
 * HTTP Post
 */
public class HttpPostTransport extends Transport {
	protected HttpPostTransport(URL url, Proxy proxy) {
		super(url, proxy);
	}
	
	@Override
	public Object sendMessage(Request msg) throws IOException, MalformedURLException {
		System.out.println("Sending " + msg + " by POST");
		byte[] body = (byte[]) msg.getMessage();
		
        URL url = getUrl(msg.getOperation());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.addRequestProperty("Content-Length", Integer.toString(body.length));

        OutputStream stream = conn.getOutputStream();
        stream.write(body);
        stream.close();

        return conn.getContent();
	}
}
