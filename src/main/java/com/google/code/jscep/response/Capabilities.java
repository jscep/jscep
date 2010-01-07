package com.google.code.jscep.response;

import java.util.EnumSet;

public class Capabilities {
	private EnumSet<Capability> capabilities;
	
	private Capabilities(Capability... capabilities) {
		this.capabilities = EnumSet.noneOf(Capability.class);
		for (Capability capability : capabilities) {
			this.capabilities.add(capability);
		}
	}
}
