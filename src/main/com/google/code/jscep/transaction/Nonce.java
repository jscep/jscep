package com.google.code.jscep.transaction;

public class Nonce {
	private byte[] nonce;
	
	public Nonce(byte[] nonce) {
		this.nonce = nonce;
	}
	
	public byte[] getBytes() {
		return nonce;
	}
}
