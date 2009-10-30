package com.google.code.jscep.asn1;

import org.bouncycastle.asn1.DERPrintableString;

public interface MessageType {
	DERPrintableString CertRep = new DERPrintableString("3");
	DERPrintableString PKCSReq = new DERPrintableString("19");
	DERPrintableString GetCertInitial= new DERPrintableString("20");
	DERPrintableString GetCert = new DERPrintableString("21");
	DERPrintableString GetCRL = new DERPrintableString("22");
}
