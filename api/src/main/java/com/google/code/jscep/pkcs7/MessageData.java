package com.google.code.jscep.pkcs7;

import org.bouncycastle.asn1.cms.ContentInfo;

public class MessageData {
	private final ContentInfo contentInfo;
	
	public MessageData(ContentInfo contentInfo) {
		this.contentInfo = contentInfo;
	}
	
	public ContentInfo getContent() {
		return contentInfo;
	}
	
	@Override
	public String toString() {
		final StringBuilder builder = new StringBuilder();
		
		builder.append("messageData [\n");
		builder.append("\tcontentType: " + contentInfo.getContentType() + "\n");
		builder.append("\tcontent: " + contentInfo.getContent() + "\n");
		builder.append("]");
		
		return builder.toString();
	}
}
