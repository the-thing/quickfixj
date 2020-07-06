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
import quickfix.DefaultMessageFactory;
import quickfix.FixVersions;
import quickfix.Initiator;
import quickfix.LogFactory;
import quickfix.MessageFactory;
import quickfix.MessageStoreFactory;
import quickfix.NoopLogFactory;
import quickfix.NoopStoreFactory;
import quickfix.Session;
import quickfix.SessionFactory;
import quickfix.SessionID;
import quickfix.SessionSettings;
import quickfix.SocketInitiator;
import quickfix.field.MDEntryType;
import quickfix.field.MDReqID;
import quickfix.field.MarketDepth;
import quickfix.field.MaturityDate;
import quickfix.field.Product;
import quickfix.field.SecurityType;
import quickfix.field.SubscriptionRequestType;
import quickfix.field.Symbol;
import quickfix.fix44.MarketDataRequest;
import quickfix.fix44.component.Instrument;
import quickfix.mina.ProtocolFactory;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Properties;

public class InitiatorBenchmark {

    private final Initiator initiator;

    public InitiatorBenchmark(Initiator initiator) {
        this.initiator = initiator;
    }

    public static void main(String[] args) throws Exception {
        BenchmarkOptions options = new BenchmarkOptions();

        Properties defaults = new Properties();
        defaults.put(SessionFactory.SETTING_CONNECTION_TYPE, SessionFactory.INITIATOR_CONNECTION_TYPE);
        defaults.put(Initiator.SETTING_SOCKET_CONNECT_PROTOCOL, ProtocolFactory.SOCKET);
        defaults.put(Session.SETTING_START_TIME, "00:00:00");
        defaults.put(Session.SETTING_END_TIME, "00:00:00");
        defaults.put(Initiator.SETTING_SOCKET_CONNECT_PROTOCOL, ProtocolFactory.SOCKET);
        defaults.put(Session.SETTING_HEARTBTINT, "30");
        defaults.put(Session.SETTING_RESET_ON_LOGON, "Y");

        SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "INITIATOR", "ACCEPTOR");

        SessionSettings sessionSettings = new SessionSettings();
        sessionSettings.set(defaults);

        sessionSettings.setString(sessionID, "BeginString", FixVersions.BEGINSTRING_FIX44);
        sessionSettings.setString(sessionID, "DataDictionary", "FIX44.xml");
        sessionSettings.setString(sessionID, "SocketConnectHost", "localhost");
        sessionSettings.setString(sessionID, "SocketConnectPort", "12345");

        // LogFactory logFactory = new SLF4JLogFactory(sessionSettings);
        LogFactory logFactory = new NoopLogFactory();
        BenchmarkApplication application = new BenchmarkApplication();
        MessageFactory messageFactory = new DefaultMessageFactory();
        MessageStoreFactory messageStoreFactory = new NoopStoreFactory();

        SocketInitiator initiator = SocketInitiator.newBuilder().withLogFactory(logFactory).withApplication(application)
                                                   .withMessageFactory(messageFactory)
                                                   .withMessageStoreFactory(messageStoreFactory)
                                                   .withSettings(sessionSettings)
                                                   .withQueueCapacity(options.getQueueCapacity()).build();

        InitiatorBenchmark benchmark = new InitiatorBenchmark(initiator);
        benchmark.executeBenchmark();
    }

    public SessionSettings createSessionSettings(BenchmarkOptions options) {
        Properties defaults = new Properties();
        defaults.put(SessionFactory.SETTING_CONNECTION_TYPE, options.getConnectionType());
        defaults.put(Initiator.SETTING_SOCKET_CONNECT_PROTOCOL, ProtocolFactory.SOCKET);
        defaults.put(Session.SETTING_START_TIME, "00:00:00");
        defaults.put(Session.SETTING_END_TIME, "00:00:00");
        defaults.put(Session.SETTING_HEARTBTINT, "30");
        defaults.put(Session.SETTING_RESET_ON_LOGON, "Y");

        SessionSettings sessionSettings = new SessionSettings();
        sessionSettings.set(defaults);

        for (int i = 0; i < options.getSessionCount(); i++) {
            SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "INITIATOR" + i, "ACCEPTOR");
        }

        return sessionSettings;
    }

    public void executeBenchmark() throws Exception {
        initiator.start();

        while (!initiator.isLoggedOn()) {
            Thread.sleep(1000);
        }

        System.out.println("All initiator sessions logged in");

        MarketDataRequest marketDataRequest = new MarketDataRequest();
        marketDataRequest.set(new MDReqID("68f523f2-e4f1-4470-acf7-d5e2e694c129"));
        marketDataRequest.set(new SubscriptionRequestType(SubscriptionRequestType.SNAPSHOT_UPDATES));
        marketDataRequest.set(new MarketDepth(10));

        MarketDataRequest.NoMDEntryTypes noMDEntryTypes = new MarketDataRequest.NoMDEntryTypes();

        noMDEntryTypes.set(new MDEntryType(MDEntryType.BID));
        marketDataRequest.addGroup(noMDEntryTypes);

        noMDEntryTypes.set(new MDEntryType(MDEntryType.OFFER));
        marketDataRequest.addGroup(noMDEntryTypes);

        Instrument instrument = new Instrument();
        instrument.set(new Symbol("EURUSD"));
        instrument.set(new Product(Product.CURRENCY));
        instrument.set(new SecurityType(SecurityType.FOREIGN_EXCHANGE_CONTRACT));
        instrument.set(new MaturityDate("20200513"));

        MarketDataRequest.NoRelatedSym noRelatedSym = new MarketDataRequest.NoRelatedSym();
        noRelatedSym.set(instrument);
        marketDataRequest.addGroup(noRelatedSym);

        int msgCount = 1_000_000;
        SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "INITIATOR", "ACCEPTOR");

        System.gc();
        Thread.sleep(20_000);
        System.out.println("Benchmark running...");

        long startTime = System.nanoTime();

        for (int i = 0; i < msgCount; i++) {
            Session.sendToTarget(marketDataRequest, sessionID);
        }

        long delta = System.nanoTime() - startTime;
        System.out.println("Benchmark end");

        long deltaSeconds = java.util.concurrent.TimeUnit.NANOSECONDS.toSeconds(delta);
        System.out.println("Delta: " + delta + ", delta seconds: " + deltaSeconds);
        BigDecimal throughput;

        if (deltaSeconds == 0) {
            throughput = BigDecimal.valueOf(msgCount);
        } else {
            throughput = BigDecimal.valueOf(msgCount).divide(BigDecimal.valueOf(deltaSeconds), RoundingMode.HALF_EVEN)
                                   .setScale(0, RoundingMode.HALF_EVEN);
        }

        System.out.println("Throughput: " + throughput.toPlainString() + " msg/s");
    }
}
