package org.jscep.client;

import java.net.URI;
import java.net.URL;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.jscep.server.ScepServletImpl;

public abstract class ScepServerSupport {
    public URL getUrl() throws Exception {
        final String path = "/scep/pkiclient.exe";
        final ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(ScepServletImpl.class.getName(), path);
        final Server server = new Server(0);
        server.setHandler(handler);
        server.start();

        URI uri = server.getURI();
        return new URL(uri.getScheme(), uri.getHost(), uri.getPort(), path);
    }
}
