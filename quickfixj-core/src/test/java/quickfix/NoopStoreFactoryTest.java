package quickfix;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class NoopStoreFactoryTest {

    private NoopStoreFactory underTest;

    @Before
    public void setUp() {
        underTest = new NoopStoreFactory();
    }

    @Test
    public void shouldCreateNoopStore() {
        SessionID sessionID = new SessionID("FIX.4.2", "SENDER", "TARGET");
        MessageStore messageStore = underTest.create(sessionID);
        assertTrue(messageStore instanceof NoopStore);
    }
}
