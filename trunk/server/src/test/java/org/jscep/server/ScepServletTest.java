package org.jscep.server;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.jscep.request.GetCaCaps;
import org.jscep.response.Capabilities;
import org.jscep.transport.Transport;
import org.jscep.transport.Transport.Method;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;


@Ignore @RunWith(Parameterized.class)
public class ScepServletTest {
	private static Server SERVER;
	private static String PATH = "/scep/pkiclient.exe";
	private static int PORT;
	private final Method method;
	
	@Parameters
	public static List<Object[]> getParameters() {
		final List<Object[]> params = new LinkedList<Object[]>();
		params.add(new Object[] {Method.GET});
		
		return params;
	}
	
	@BeforeClass
	public static void startServer() throws Exception {
		SERVER = new Server(0);
		final ServletHandler handler = new ServletHandler();
		handler.addServletWithMapping(ScepServletImpl.class, PATH);
		SERVER.setHandler(handler);
		SERVER.start();
		PORT = SERVER.getConnectors()[0].getLocalPort();
	}
	
	public ScepServletTest(Method method) {
		this.method = method;
	}
	
	private URL getURL() throws MalformedURLException {
		return new URL("http", "localhost", PORT, PATH);
	}
	
	@Test
	public void basicTest() throws Exception {
		GetCaCaps req = new GetCaCaps(null);
		Transport transport = Transport.createTransport(method, getURL());
		Capabilities caps = transport.sendRequest(req);
		
		System.out.println(caps);
	}
}
