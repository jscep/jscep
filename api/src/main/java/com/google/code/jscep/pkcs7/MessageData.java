package com.google.code.jscep.pkcs7;

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;

public class MessageData {
	private final ContentInfo contentInfo;
	
	public MessageData(ContentInfo contentInfo) {
		this.contentInfo = contentInfo;
	}
	
	public ContentInfo getContent() {
		return contentInfo;
	}
	
	public static MessageData getInstance(DEREncodable content) {
		ContentInfo info = new ContentInfo(CMSObjectIdentifiers.data, content);
		
		return new MessageData(info);
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
