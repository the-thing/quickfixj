package org.quickfixj.benchmark;

import org.quickfixj.benchmark.options.BenchmarkOptions;
import quickfix.Acceptor;
import quickfix.DefaultMessageFactory;
import quickfix.FixVersions;
import quickfix.Initiator;
import quickfix.LogFactory;
import quickfix.MessageFactory;
import quickfix.MessageStoreFactory;
import quickfix.NoopStoreFactory;
import quickfix.SLF4JLogFactory;
import quickfix.Session;
import quickfix.SessionFactory;
import quickfix.SessionID;
import quickfix.SessionSettings;
import quickfix.SocketAcceptor;
import quickfix.mina.ProtocolFactory;

import java.util.Properties;

public class AcceptorBenchmark {

    private final Acceptor acceptor;

    public AcceptorBenchmark(Acceptor acceptor) {
        this.acceptor = acceptor;
    }

    public static void main(String[] args) throws Exception {
        Properties defaults = new Properties();
        defaults.put(SessionFactory.SETTING_CONNECTION_TYPE, SessionFactory.ACCEPTOR_CONNECTION_TYPE);
        defaults.put(Initiator.SETTING_SOCKET_CONNECT_PROTOCOL, ProtocolFactory.SOCKET);
        defaults.put(Session.SETTING_START_TIME, "00:00:00");
        defaults.put(Session.SETTING_END_TIME, "00:00:00");
        defaults.put(Initiator.SETTING_SOCKET_CONNECT_PROTOCOL, ProtocolFactory.SOCKET);
        defaults.put(Session.SETTING_HEARTBTINT, "30");
        defaults.put(Session.SETTING_RESET_ON_LOGON, "Y");

        BenchmarkOptions options = new BenchmarkOptions();

        SessionSettings sessionSettings = new SessionSettings();
        sessionSettings.set(defaults);

        SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "ACCEPTOR", "INITIATOR");
        sessionSettings.setString(sessionID, Acceptor.SETTING_SOCKET_ACCEPT_ADDRESS, "localhost");
        sessionSettings.setString(sessionID, Acceptor.SETTING_SOCKET_ACCEPT_PORT, "12345");

        LogFactory logFactory = new SLF4JLogFactory(sessionSettings);
        BenchmarkApplication application = new BenchmarkApplication();
        MessageFactory messageFactory = new DefaultMessageFactory();
        MessageStoreFactory messageStoreFactory = new NoopStoreFactory();

        SocketAcceptor acceptor = SocketAcceptor.newBuilder().withLogFactory(logFactory).withApplication(application)
                                                .withMessageFactory(messageFactory)
                                                .withMessageStoreFactory(messageStoreFactory)
                                                .withSettings(sessionSettings)
                                                .withQueueCapacity(options.getQueueCapacity()).build();

        AcceptorBenchmark benchmark = new AcceptorBenchmark(acceptor);
        benchmark.executeBenchmark();
    }

    public void executeBenchmark() throws Exception {
        acceptor.start();

        while (!acceptor.isLoggedOn()) {
            Thread.sleep(1000);
        }

        System.out.println("All acceptor sessions logged in");

        while (true) {
            Thread.sleep(2000);
        }
    }
}
