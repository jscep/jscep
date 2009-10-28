package com.google.code.jscep;

import org.bouncycastle.util.encoders.Base64;

public class ScepMessage {
    private byte[] binary;
    private String string;

    public ScepMessage(String msg) {
        this.binary = msg.getBytes();
        this.string = msg;
    }

    public ScepMessage(byte[] msg) {
        this.binary = msg;
        this.string = new String(Base64.encode(msg));
    }

    public byte[] getBytes() {
        return binary;
    }

    public String toString() {
        return string;
    }
}
