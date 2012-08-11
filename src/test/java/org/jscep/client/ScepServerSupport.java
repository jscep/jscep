package org.jscep.client;

import java.net.URL;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.jscep.server.ScepServletImpl;

public abstract class ScepServerSupport {
	public URL getUrl() throws Exception {
		final String path = "/scep/pkiclient.exe";
		final ServletHandler handler = new ServletHandler();
		handler.addServletWithMapping(ScepServletImpl.class, path);
		final Server server = new Server(0);
		server.setHandler(handler);
		server.start();
		
		final int port = server.getConnectors()[0].getLocalPort();
		return new URL("http", "localhost", port, path);
	}
}
