/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.content;

import com.google.code.jscep.response.CaCapabilitiesResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ContentHandler;
import java.net.URLConnection;

public class CaCapabilitiesResponseHandler extends ContentHandler {
    public Object getContent(URLConnection conn) throws IOException {

        CaCapabilitiesResponse response = new CaCapabilitiesResponse();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String capability;

        while ((capability = reader.readLine()) != null) {
            for (CaCapabilitiesResponse.Capability capabilityEnum : CaCapabilitiesResponse.Capability.values()) {
                if (capabilityEnum.getName().equals(capability.trim())) {
                    response.add(capabilityEnum);
                }
            }
        }

        reader.close();

        return response;
    }
}
