package org.jscep.state;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.jscep.message.CertRep;
import org.jscep.message.PkiMessage;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.PkiStatus;

public class StateMachine {
	public static enum State {
		INITIAL,
		WAITING,
		PENDING,
		FAILURE,
		SUCCESS
	}

	private List<PkiMessage<?>> messages;
	private State currentState;
	
	public StateMachine() {
		messages = new ArrayList<PkiMessage<?>>();
		currentState = State.INITIAL;
	}
	
	public void updateState(PkiMessage<? extends ASN1Encodable> pkiMessage) {
		MessageType messageType = pkiMessage.getMessageType();
		
		if (currentState == State.INITIAL) {
			if (messageType == MessageType.CertRep) {
				throw new IllegalStateException();
			} else {
				// We're sending out our first message
				currentState = State.WAITING;
			}
		} else if (currentState == State.WAITING) {
			if (messageType != MessageType.CertRep) {
				throw new IllegalStateException();
			} else {
				CertRep certRep = (CertRep) pkiMessage;
				PkiStatus status = certRep.getPkiStatus();
				
				if (status == PkiStatus.FAILURE) {
					currentState = State.FAILURE;
				} else  if (status == PkiStatus.PENDING) {
					currentState = State.PENDING;
				} else {
					currentState = State.SUCCESS;
				}
			}
		} else if (currentState == State.SUCCESS) {
			// Shouldn't be sending any more messages!
			throw new IllegalStateException();
		} else if (currentState == State.FAILURE) {
			if (messageType != MessageType.PKCSReq) {
				throw new IllegalStateException();
			} else {
				currentState = State.WAITING;
			}
		} else if (currentState == State.PENDING) {
			if (messageType != MessageType.GetCertInitial) {
				throw new IllegalStateException();
			} else {
				currentState = State.WAITING;
			}
		} else {
			throw new IllegalStateException();
		}
		
		messages.add(pkiMessage);
	}
	
	public State getState() {
		return currentState;
	}
}
