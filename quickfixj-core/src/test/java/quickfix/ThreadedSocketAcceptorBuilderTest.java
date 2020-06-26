package quickfix;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.junit.Assert.assertNotNull;

@RunWith(MockitoJUnitRunner.class)
public class ThreadedSocketAcceptorBuilderTest {

    @Mock
    private Application application;
    @Mock
    private LogFactory logFactory;
    @Mock
    private MessageFactory messageFactory;
    @Mock
    private MessageStoreFactory messageStoreFactory;
    @Mock
    private SessionSettings sessionSettings;

    @Test
    public void shouldBuildDefaultThreadedSocketAcceptor() throws ConfigError {
        ThreadedSocketAcceptor acceptor = ThreadedSocketAcceptor.newBuilder().withSettings(sessionSettings).build();
        assertNotNull(acceptor);
    }

    @Test
    public void shouldBuildCustomThreadedSocketAcceptorWithQueueCapacity() throws ConfigError {
        ThreadedSocketAcceptor acceptor = ThreadedSocketAcceptor.newBuilder().withApplication(application)
                                                                .withLogFactory(logFactory)
                                                                .withMessageFactory(messageFactory)
                                                                .withMessageStoreFactory(messageStoreFactory)
                                                                .withQueueCapacity(4096).withSettings(sessionSettings)
                                                                .build();
        assertNotNull(acceptor);
    }

    @Test
    public void shouldBuildCustomThreadedSocketAcceptorWithWatermarks() throws ConfigError {
        ThreadedSocketAcceptor acceptor = ThreadedSocketAcceptor.newBuilder().withApplication(application)
                                                                .withLogFactory(logFactory)
                                                                .withMessageFactory(messageFactory)
                                                                .withMessageStoreFactory(messageStoreFactory)
                                                                .withQueueWatermarks(16, 64)
                                                                .withSettings(sessionSettings).build();
        assertNotNull(acceptor);
    }
}
