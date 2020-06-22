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

import org.quickfixj.benchmark.options.BenchmarkOptions;
import quickfix.ConfigError;
import quickfix.DefaultMessageFactory;
import quickfix.Initiator;
import quickfix.LogFactory;
import quickfix.MessageFactory;
import quickfix.MessageStoreFactory;
import quickfix.NoopStoreFactory;
import quickfix.SLF4JLogFactory;
import quickfix.SessionSettings;
import quickfix.ThreadedSocketInitiator;

public class InitiatorBenchmark {

    private final Initiator initiator;

    public InitiatorBenchmark(Initiator initiator) {
        this.initiator = initiator;
    }

    public static void main(String[] args) throws ConfigError {
        BenchmarkOptions options = new BenchmarkOptions();
        SessionSettings sessionSettings = new SessionSettings();

        LogFactory logFactory = new SLF4JLogFactory(sessionSettings);
        BenchmarkApplication application = new BenchmarkApplication();
        MessageFactory messageFactory = new DefaultMessageFactory();
        MessageStoreFactory messageStoreFactory = new NoopStoreFactory();

        ThreadedSocketInitiator initiator = ThreadedSocketInitiator.newBuilder().withLogFactory(logFactory)
                                                                   .withApplication(application)
                                                                   .withMessageFactory(messageFactory)
                                                                   .withMessageStoreFactory(messageStoreFactory)
                                                                   .withSettings(sessionSettings)
                                                                   .withQueueCapacity(options.getQueueCapacity())
                                                                   .withQueueWatermarks(
                                                                           options.getQueueLowerWatermark(),
                                                                           options.getQueueUpperWatermark()).build();

        initiator.start();
    }

    private void executeBenchmark() {
    }
}
