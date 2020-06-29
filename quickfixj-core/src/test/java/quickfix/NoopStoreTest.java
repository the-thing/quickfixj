package quickfix;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

public class NoopStoreTest {

    private NoopStore underTest;

    @Before
    public void setUp() {
        underTest = new NoopStore();
    }

    @Test
    public void shouldCreateWithDefaultProperties() {
        assertNotNull(underTest.getCreationTime());
        assertEquals(1, underTest.getNextSenderMsgSeqNum());
        assertEquals(1, underTest.getNextTargetMsgSeqNum());
    }

    @Test
    public void shouldIncrementNextSenderMsgSequenceNumber() {
        underTest.incrNextSenderMsgSeqNum();

        assertEquals(2, underTest.getNextSenderMsgSeqNum());
    }

    @Test
    public void shouldSetNextSenderMsgSequenceNumber() {
        underTest.setNextSenderMsgSeqNum(123);

        assertEquals(123, underTest.getNextSenderMsgSeqNum());
    }

    @Test
    public void shouldIncrementNextTargetMsgSequenceNumber() {
        underTest.incrNextTargetMsgSeqNum();

        assertEquals(2, underTest.getNextTargetMsgSeqNum());
    }

    @Test
    public void shouldSetNextTargetMsgSequenceNumber() {
        underTest.setNextTargetMsgSeqNum(123);

        assertEquals(123, underTest.getNextTargetMsgSeqNum());
    }

    @Test
    public void shouldReset() {
        underTest.setNextTargetMsgSeqNum(222);
        underTest.setNextSenderMsgSeqNum(333);
        underTest.reset();

        assertEquals(1, underTest.getNextSenderMsgSeqNum());
        assertEquals(1, underTest.getNextTargetMsgSeqNum());
    }

    @Test
    public void shouldAddMessage() {
        boolean added = underTest.set(434, "message");

        assertTrue(added);
    }

    @Test
    public void shouldGetNoMessages() {
        underTest.set(1, "message1");
        underTest.set(2, "message2");

        List<String> messages = new ArrayList<>();
        underTest.get(1, 2, messages);

        assertEquals(0, messages.size());
    }
}
