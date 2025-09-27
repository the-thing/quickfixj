package quickfix;

import org.apache.mina.util.AvailablePortFinder;
import org.hsqldb.Server;
import org.junit.Assert;
import org.junit.Test;
import quickfix.field.MsgSeqNum;
import quickfix.field.MsgType;
import quickfix.field.TestReqID;
import quickfix.field.UserRequestID;
import quickfix.fix44.QuoteStatusReport;
import quickfix.fix44.TestRequest;
import quickfix.fix44.UserRequest;
import quickfix.fix44.UserResponse;
import quickfix.mina.ProtocolFactory;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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

    private static void initTables(SessionSettings initiatorSettings) throws Exception {
        SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "JDBC_INITIATOR", "JDBC_ACCEPTOR");

        String jdbcDriver = initiatorSettings.getString(sessionID, JdbcSetting.SETTING_JDBC_DRIVER);
        Class<?> driverClass = Class.forName(jdbcDriver);
        requireNonNull(driverClass);

        String connectionUrl = initiatorSettings.getString(sessionID, JdbcSetting.SETTING_JDBC_CONNECTION_URL);
        String user = initiatorSettings.getString(sessionID, JdbcSetting.SETTING_JDBC_USER);
        String password = initiatorSettings.getString(sessionID, JdbcSetting.SETTING_JDBC_PASSWORD);

        try (Connection connection = DriverManager.getConnection(connectionUrl, user, password)) {
            executeSql(connection, "config/sql/hsqldb/sessions_table.sql", new JdbcTestSupport.HypersonicPreprocessor("sessions")::preprocessSQL);
            executeSql(connection, "config/sql/hsqldb/messages_table.sql", new JdbcTestSupport.HypersonicPreprocessor("messages")::preprocessSQL);
        }
    }

    private static void initTables(DataSource dataSource) throws Exception {
        SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "JDBC_INITIATOR", "JDBC_ACCEPTOR");

        try (Connection connection = dataSource.getConnection()) {
            executeSql(connection, "config/sql/hsqldb/sessions_table.sql", new JdbcTestSupport.HypersonicPreprocessor("sessions")::preprocessSQL);
            executeSql(connection, "config/sql/hsqldb/messages_table.sql", new JdbcTestSupport.HypersonicPreprocessor("messages")::preprocessSQL);
        }
    }

    private static void executeSql(Connection connection, String sqlResource, Function<String, String> preprocessor) throws IOException, SQLException {
        try (InputStream in = JdbcStoreEndToEndTest.class.getClassLoader().getResourceAsStream(sqlResource)) {
            String sql = getString(in);
            sql = preprocessor.apply(sql);

            try (Statement statement = connection.createStatement()) {
                statement.execute(sql);
            }
        }
    }

    private static String getString(InputStream in) throws IOException {
        StringBuilder out = new StringBuilder(in.available());
        char[] buffer = new char[4096];

        try (InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            int readCharCount;

            while ((readCharCount = reader.read(buffer)) != -1) {
                out.append(buffer, 0, readCharCount);
            }
        }

        return out.toString();
    }

    @Test
    public void foo() throws Exception {
        int connectPort = AvailablePortFinder.getNextAvailable();

        ThreadedSocketAcceptor acceptor = new ThreadedSocketAcceptor(new AcceptorApplication(), new MemoryStoreFactory(), createAcceptorSettings(connectPort), new DefaultMessageFactory());
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

                SessionID sessionID = new SessionID(FixVersions.BEGINSTRING_FIX44, "JDBC_INITIATOR", "JDBC_ACCEPTOR");
                DataSource dataSource = JdbcUtil.getDataSource(initiatorSettings, sessionID);
                initTables(dataSource);

                JdbcStoreFactory storeFactory = new JdbcStoreFactory(initiatorSettings);
                storeFactory.setDataSource(dataSource);

                InitiatorApplication capturingApplication = new InitiatorApplication();
                ThreadedSocketInitiator initiator = new ThreadedSocketInitiator(capturingApplication, storeFactory, initiatorSettings, new DefaultMessageFactory());
                initiator.start();

                try {
                    Thread.sleep(2_000);

                    int msgCount = 100;
                    Session session = Session.lookupSession(sessionID);
                    assertNotNull(session);

                    for (int i = 0; i < msgCount; i++) {
                        UserRequest userRequest = new UserRequest();
                        userRequest.set(new UserRequestID(UUID.randomUUID().toString()));
                        session.send(userRequest);
                    }

                } finally {
                    initiator.stop();
                }

                try (Connection connection = dataSource.getConnection()) {
                    Statement statement = connection.createStatement();
                    ResultSet result = statement.executeQuery("select incoming_seqnum, outgoing_seqnum from sessions;");
                    assertTrue(result.next());

                    int dbInSeqNum = result.getInt("incoming_seqnum");
                    int dbOutSeqNum = result.getInt("outgoing_seqnum");

                    int appInSeqNum = capturingApplication.inSeqNum;
                    int appOutSeqNum = capturingApplication.outSeqNum;

                    System.out.println("ml_test, DB = " + dbInSeqNum + " / " + dbOutSeqNum);
                    System.out.println("ml_test, APP = " + appInSeqNum + " / " + appOutSeqNum);

                    assertEquals(dbInSeqNum, appInSeqNum + 1);
                    assertEquals(dbOutSeqNum, appOutSeqNum + 1);
                }
            } finally {
                dbServer.start();
            }
        } finally {
            acceptor.stop();
        }
    }

    private static final class InitiatorApplication extends ApplicationAdapter {

        private int inSeqNum;
        private int outSeqNum;

        @Override
        public void fromAdmin(Message message, SessionID sessionId) throws FieldNotFound {
            captureIncomingSequence(message);
        }

        @Override
        public void fromApp(Message message, SessionID sessionId) throws FieldNotFound {
            captureIncomingSequence(message);
        }

        @Override
        public void toAdmin(Message message, SessionID sessionId) {
            captureOutgoingSequence(message);
        }

        @Override
        public void toApp(Message message, SessionID sessionId) {
            captureOutgoingSequence(message);
        }

        private void captureIncomingSequence(Message message) throws FieldNotFound {
            Message.Header header = message.getHeader();
            inSeqNum = header.getInt(MsgSeqNum.FIELD);
        }

        private void captureOutgoingSequence(Message message) {
            Message.Header header = message.getHeader();

            try {
                outSeqNum = header.getInt(MsgSeqNum.FIELD);
            } catch (FieldNotFound e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static final class AcceptorApplication extends ApplicationAdapter {

        @Override
        public void fromApp(Message message, SessionID sessionId) throws FieldNotFound {
            Message.Header header = message.getHeader();
            String msgType = header.getString(MsgType.FIELD);

            if (UserRequest.MSGTYPE.equals(msgType)) {
                String userRequestId = message.getString(UserRequestID.FIELD);

                UserResponse userResponse = new UserResponse();
                userResponse.set(new UserRequestID(userRequestId));

                Session session = Session.lookupSession(sessionId);
                session.send(userResponse);
            }
        }
    }
}
