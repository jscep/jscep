package org.jscep.transport;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public class ParameterizedSSLSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory _factory;
    private final SSLParameters _parameters;

    ParameterizedSSLSocketFactory(SSLSocketFactory factory, SSLParameters parameters) {
        this._factory = factory;
        this._parameters = parameters;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) _factory.createSocket(host, port);
        socket.setSSLParameters(_parameters);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) _factory.createSocket(host, port, localHost, localPort);
        socket.setSSLParameters(_parameters);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) _factory.createSocket(host, port);
        socket.setSSLParameters(_parameters);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) _factory.createSocket(address, port, localAddress, localPort);
        socket.setSSLParameters(_parameters);
        return socket;

    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        SSLSocket socket = (SSLSocket) _factory.createSocket(s, host, port, autoClose);
        socket.setSSLParameters(_parameters);
        return socket;
    }

    @Override
    public Socket createSocket() throws IOException {
        SSLSocket socket = (SSLSocket) _factory.createSocket();
        socket.setSSLParameters(_parameters);
        return socket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return _factory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return _factory.getSupportedCipherSuites();
    }
}
