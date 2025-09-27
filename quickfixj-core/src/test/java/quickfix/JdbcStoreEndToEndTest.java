package quickfix;

import org.apache.mina.util.AvailablePortFinder;
import org.hsqldb.Server;
import org.junit.Before;
import org.junit.Test;
import quickfix.mina.ProtocolFactory;

public class JdbcStoreEndToEndTest {

    private static SessionSettings createInitiatorSettings(int connectPort, int dbPort) {
        SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "JDBC_INITIATOR", "JDBC_ACCEPTOR");

        SessionSettings sessionSettings = new SessionSettings();

        sessionSettings.setString(SessionFactory.SETTING_CONNECTION_TYPE, "initiator");
        sessionSettings.setString(Initiator.SETTING_SOCKET_CONNECT_PROTOCOL, ProtocolFactory.getTypeString(ProtocolFactory.SOCKET));
        sessionSettings.setString(Initiator.SETTING_SOCKET_CONNECT_HOST, "localhost");
        sessionSettings.setString(Initiator.SETTING_SOCKET_CONNECT_PORT, Integer.toString(connectPort));
        sessionSettings.setString(Initiator.SETTING_RECONNECT_INTERVAL, "2");
        sessionSettings.setString(Session.SETTING_START_TIME, "00:00:00");
        sessionSettings.setString(Session.SETTING_END_TIME, "00:00:00");
        sessionSettings.setString(Session.SETTING_HEARTBTINT, "30");

        sessionSettings.setString(JdbcSetting.SETTING_JDBC_DRIVER, "org.hsqldb.jdbcDriver");
        sessionSettings.setString(JdbcSetting.SETTING_JDBC_CONNECTION_URL, "jdbc:hsqldb:hsql://127.0.0.1:" + dbPort + "/quickfix-jdbc-test");
        sessionSettings.setString(JdbcSetting.SETTING_JDBC_USER, "SA");
        sessionSettings.setString(JdbcSetting.SETTING_JDBC_PASSWORD, "");
        sessionSettings.setString(JdbcSetting.SETTING_JDBC_CONNECTION_TEST_QUERY, "CALL NOW()");

        sessionSettings.setString(sessionID, SessionSettings.BEGINSTRING, FixVersions.BEGINSTRING_FIX44);
        sessionSettings.setString(sessionID, Session.SETTING_DATA_DICTIONARY, "FIX44.xml");
        sessionSettings.setString(sessionID, SessionSettings.SENDERCOMPID, "JDBC_INITIATOR");
        sessionSettings.setString(sessionID, SessionSettings.TARGETCOMPID, "JDBC_ACCEPTOR");

        return sessionSettings;
    }

    private static SessionSettings createAcceptorSettings(int acceptPort) {
        SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "JDBC_ACCEPTOR", "JDBC_INITIATOR");

        SessionSettings sessionSettings = new SessionSettings();

        sessionSettings.setString(SessionFactory.SETTING_CONNECTION_TYPE, "acceptor");
        sessionSettings.setString(Acceptor.SETTING_SOCKET_ACCEPT_PORT, Integer.toString(acceptPort));
        sessionSettings.setString(Session.SETTING_START_TIME, "00:00:00");
        sessionSettings.setString(Session.SETTING_END_TIME, "00:00:00");
        sessionSettings.setString(Session.SETTING_HEARTBTINT, "30");

        sessionSettings.setString(sessionID, SessionSettings.BEGINSTRING, FixVersions.BEGINSTRING_FIX44);
        sessionSettings.setString(sessionID, Session.SETTING_DATA_DICTIONARY, "FIX44.xml");
        sessionSettings.setString(sessionID, SessionSettings.SENDERCOMPID, "JDBC_ACCEPTOR");
        sessionSettings.setString(sessionID, SessionSettings.TARGETCOMPID, "JDBC_INITIATOR");

        return sessionSettings;
    }

    @Before
    public void setUp() {
    }

    @Test
    public void foo() throws ConfigError, InterruptedException {
        int connectPort = AvailablePortFinder.getNextAvailable();

        ThreadedSocketAcceptor acceptor = new ThreadedSocketAcceptor(new ApplicationAdapter(), new MemoryStoreFactory(), createAcceptorSettings(connectPort), new DefaultMessageFactory());
        acceptor.start();

        try {
            int dbPort = AvailablePortFinder.getNextAvailable();

            Server dbServer = new Server();
            dbServer.setDatabaseName(0, "quickfix-jdbc-test");
            dbServer.setDatabasePath(0, "mem:quickfix-jdbc-test");
            dbServer.setAddress("127.0.0.1");
            dbServer.setPort(dbPort);
            dbServer.start();

            try {
                SessionSettings initiatorSettings = createInitiatorSettings(connectPort, dbPort);
                JdbcStoreFactory storeFactory = new JdbcStoreFactory(initiatorSettings);

                ThreadedSocketInitiator initiator = new ThreadedSocketInitiator(new ApplicationAdapter(), storeFactory, initiatorSettings, new DefaultMessageFactory());
                initiator.start();

                try {
                    Thread.sleep(2_000);
                    System.out.println("ml_test = " + initiator.isLoggedOn());
                } finally {
                    initiator.stop();
                }
            } finally {
                dbServer.start();
            }
        } finally {
            acceptor.stop();
        }
    }
}
