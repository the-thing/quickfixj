package quickfix.mina.ssl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;

import javax.net.ssl.SSLContext;

import org.junit.Before;
import org.junit.Test;

/**
 * Test for {@link SSLContextFactory}
 *
 * @author toli
 */
public class SSLContextFactoryTest {

    private SSLContextFactory underTest;

    @Before
    public void setUp() {
        underTest = new SSLContextFactory();
    }

    @Test
    public void testGetInstance() throws Exception {
        SSLConfig sslConfig = new SSLConfig();
        sslConfig.setKeyStoreName(SSLSupport.QUICKFIXJ_KEY_STORE);
        sslConfig.setKeyStorePassword(SSLSupport.QUICKFIXJ_KEY_STORE_PWD.toCharArray());
        sslConfig.setKeyStoreType("JKS");
        sslConfig.setKeyManagerFactoryAlgorithm("SunX509");
        sslConfig.setTrustStoreName("nonexistent");
        sslConfig.setTrustStoreType("JKS");
        sslConfig.setTrustManagerFactoryAlgorithm("PKIX");

        SSLContext context = underTest.getInstance(sslConfig);
        assertNotNull(context);
        assertNotNull(context.getProvider());
    }

    @Test
    public void testGetInstanceWithBadCert() throws Exception {
        SSLConfig sslConfig = new SSLConfig();
        sslConfig.setKeyStoreName("FOO");
        sslConfig.setKeyStorePassword("BAR".toCharArray());
        sslConfig.setKeyStoreType("JKS");
        sslConfig.setKeyManagerFactoryAlgorithm("SunX509");

        underTest.getInstance(sslConfig);
    }

    @Test
    public void shouldUseCachedSslContextForTheSameConfiguration() throws Exception {
        SSLConfig sslConfig1 = new SSLConfig();
        sslConfig1.setKeyStoreName("keystore");
        sslConfig1.setKeyStorePassword("password".toCharArray());
        sslConfig1.setKeyStoreType("JKS");
        sslConfig1.setKeyManagerFactoryAlgorithm("SunX509");

        SSLContext sslContext1 = underTest.getInstance(sslConfig1);

        SSLConfig sslConfig2 = new SSLConfig();
        sslConfig2.setKeyStoreName("keystore");
        sslConfig2.setKeyStorePassword("password".toCharArray());
        sslConfig2.setKeyStoreType("JKS");
        sslConfig2.setKeyManagerFactoryAlgorithm("SunX509");

        SSLContext sslContext2 = underTest.getInstance(sslConfig2);

        assertSame(sslContext1, sslContext2);
    }

    @Test
    public void shouldUseNewContext() throws Exception {
        SSLConfig sslConfig1 = new SSLConfig();
        sslConfig1.setKeyStoreName("keystore1");
        sslConfig1.setKeyStorePassword("password".toCharArray());
        sslConfig1.setKeyStoreType("JKS");
        sslConfig1.setKeyManagerFactoryAlgorithm("SunX509");

        SSLContext sslContext1 = underTest.getInstance(sslConfig1);

        SSLConfig sslConfig2 = new SSLConfig();
        sslConfig2.setKeyStoreName("keystore2");
        sslConfig2.setKeyStorePassword("password".toCharArray());
        sslConfig2.setKeyStoreType("JKS");
        sslConfig2.setKeyManagerFactoryAlgorithm("SunX509");

        SSLContext sslContext2 = underTest.getInstance(sslConfig2);

        assertNotSame(sslContext1, sslContext2);
    }
}
