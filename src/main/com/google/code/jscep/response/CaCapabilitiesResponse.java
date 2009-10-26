/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.response;

import java.util.HashSet;
import java.util.Set;

public class CaCapabilitiesResponse implements ScepResponse {
    public static enum Capability {
        GET_NEXT_CA_CERT("GetNextCACert"),
        POST_PKI_OPERATION("POSTPKIOperation"),
        RENEWAL("Renewal"),
        SHA_512("SHA-512"),
        SHA_256("SHA-256"),
        SHA_1("SHA-1"),
        TRIPLE_DES("DES3");

        private final String name;

        Capability(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    private Set<Capability> capabilties = new HashSet<Capability>();

    public void add(Capability capability) {
        capabilties.add(capability);
    }

    private boolean supports(Capability capability) {
        return capabilties.contains(capability);
    }

    public boolean supportsNextCaCert() {
        return supports(Capability.GET_NEXT_CA_CERT);
    }

    public boolean supportsPost() {
        return supports(Capability.POST_PKI_OPERATION);
    }

    public boolean supportsRenewal() {
        return supports(Capability.RENEWAL);
    }

    public boolean supportsSha1() {
        return supports(Capability.SHA_1);
    }

    public boolean supportsSha256() {
        return supports(Capability.SHA_256);
    }

    public boolean supportsSha512() {
        return supports(Capability.SHA_512);
    }

    public boolean supportsTripleDes() {
       return supports(Capability.TRIPLE_DES);
    }
}
