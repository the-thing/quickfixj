package quickfix;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@RunWith(MockitoJUnitRunner.class)
public class CompositeLogFactoryTest {

    private CompositeLogFactory underTest;

    @Mock
    private LogFactory logFactory1;
    @Mock
    private LocationAwareLogFactory logFactory2;

    @Before
    public void setUp() {
        doReturn(mock(Log.class)).when(logFactory1).create(any(SessionID.class));
        doReturn(mock(Log.class)).when(logFactory2).create(any(SessionID.class));

        underTest = new CompositeLogFactory(logFactory1, logFactory2);
    }

    @Test
    public void shouldCreateCompositeLog() {
        SessionID sessionID = new SessionID("FIX.4.4", "SENDER", "TARGET");
        Log log = underTest.create(sessionID);
        assertTrue(log instanceof CompositeLog);

        verify(logFactory1).create(sessionID);
        verifyNoMoreInteractions(logFactory1);

        verify(logFactory2).create(sessionID, "quickfix.CompositeLog");
        verifyNoMoreInteractions(logFactory2);
    }
}
