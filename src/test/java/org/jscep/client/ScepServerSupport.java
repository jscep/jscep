package org.jscep.client;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.NetworkConnector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.jscep.server.ScepServletImpl;

import java.net.URL;

public abstract class ScepServerSupport {

    static final String PATH = "/scep/pkiclient.exe";

    public URL getUrl() throws Exception {
        final Server server = new Server(0);
        NetworkConnector connector = new ServerConnector(server);
        server.addConnector(connector);

        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        server.setHandler(context);
        context.addServlet(ScepServletImpl.class, PATH);

        server.start();
        final int port = connector.getLocalPort();

        return new URL("http", "localhost", port, PATH);
    }
}
