package org.jscep.client;

import java.net.URL;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.jscep.server.ScepServletImpl;
import org.junit.Before;

public abstract class ScepServerSupport {
	private static String PATH = "/scep/pkiclient.exe";
	private Server server;
	private URL url;
	private int port;
	
	@Before
	public void setUp() throws Exception {
		final ServletHandler handler = new ServletHandler();
		handler.addServletWithMapping(ScepServletImpl.class, PATH);
		server = new Server(0);
		server.setHandler(handler);
		server.start();
		port = server.getConnectors()[0].getLocalPort();
		url = new URL("http", "localhost", port, PATH);
	}
	
	public URL getUrl() {
		return url;
	}
}
