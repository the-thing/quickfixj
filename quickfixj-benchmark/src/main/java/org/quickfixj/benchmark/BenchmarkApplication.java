/*******************************************************************************
 * Copyright (c) quickfixengine.org  All rights reserved.
 *
 * This file is part of the QuickFIX FIX Engine
 *
 * This file may be distributed under the terms of the quickfixengine.org
 * license as defined by quickfixengine.org and appearing in the file
 * LICENSE included in the packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING
 * THE WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * See http://www.quickfixengine.org/LICENSE for licensing information.
 *
 * Contact ask@quickfixengine.org if any conditions of this licensing
 * are not clear to you.
 ******************************************************************************/

package org.quickfixj.benchmark;

import quickfix.ApplicationAdapter;
import quickfix.FieldNotFound;
import quickfix.Message;
import quickfix.SessionID;
import quickfix.field.MsgType;

import java.util.concurrent.atomic.LongAdder;

public class BenchmarkApplication extends ApplicationAdapter {

    private LongAdder errorCount;
    private LongAdder sessionMessagesSentCount;
    private LongAdder sessionMessagesReceivedCount;
    private LongAdder applicationMessagesSentCount;
    private LongAdder applicationMessagesReceivedCount;

    public BenchmarkApplication() {
        this.errorCount = new LongAdder();
        this.sessionMessagesSentCount = new LongAdder();
        this.sessionMessagesReceivedCount = new LongAdder();
        this.applicationMessagesReceivedCount = new LongAdder();
        this.applicationMessagesSentCount = new LongAdder();
    }

    @Override
    public void fromAdmin(Message message, SessionID sessionId) throws FieldNotFound {
        sessionMessagesReceivedCount.increment();
        incrementErrorsWhenRejected(message);
    }

    @Override
    public void fromApp(Message message, SessionID sessionId) {
        applicationMessagesReceivedCount.increment();
    }

    @Override
    public void toAdmin(Message message, SessionID sessionId) {
        sessionMessagesSentCount.increment();
        incrementErrorsWhenRejected(message);
    }

    @Override
    public void toApp(Message message, SessionID sessionId) {
        applicationMessagesSentCount.increment();
    }

    private void incrementErrorsWhenRejected(Message message) {
        Message.Header header = message.getHeader();

        if (header.isSetField(MsgType.FIELD)) {
            try {
                String msgType = header.getString(MsgType.FIELD);

                if (MsgType.REJECT.equals(msgType)) {
                    errorCount.increment();
                }
            } catch (FieldNotFound e) {
                e.printStackTrace();
                errorCount.increment();
            }
        }
    }

    public long getErrorCount() {
        return errorCount.sum();
    }

    public long getSessionMessagesSentCount() {
        return sessionMessagesSentCount.sum();
    }

    public long getSessionMessagesReceivedCount() {
        return sessionMessagesReceivedCount.sum();
    }

    public long getApplicationMessagesSentCount() {
        return applicationMessagesSentCount.sum();
    }

    public long getApplicationMessagesReceivedCount() {
        return applicationMessagesReceivedCount.sum();
    }
}
