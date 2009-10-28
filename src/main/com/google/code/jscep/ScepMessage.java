package com.google.code.jscep;

import org.bouncycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class ScepMessage {
    private byte[] binary;
    private String string;

    public ScepMessage(String msg) {
        if (msg == null) {
            this.binary = null;
        } else {
            this.binary = msg.getBytes();
        }
        this.string = msg;
    }

    public ScepMessage(byte[] msg) {
        this.binary = msg;
        try {
            this.string = URLEncoder.encode(new String(Base64.encode(msg)), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e); 
        }
    }

    public byte[] getBytes() {
        return binary;
    }

    public String toString() {
        return string;
    }
}
