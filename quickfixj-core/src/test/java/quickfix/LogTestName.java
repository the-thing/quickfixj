package quickfix;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import java.security.NoSuchAlgorithmException;

public final class LogTestName implements TestRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(LogTestName.class);

    @Override
    public Statement apply(Statement base, Description description) {
        LOGGER.info("{} [{}] Running test '{}#{}'", System.currentTimeMillis(), Thread.currentThread(), description.getClassName(), description.getMethodName());

        try {
            SSLServerSocketFactory sslServerSocketFactory = SSLContext.getDefault().getServerSocketFactory();
            String[] supportedCipherSuites = sslServerSocketFactory.getSupportedCipherSuites();
            String[] defaultCipherSuites = sslServerSocketFactory.getDefaultCipherSuites();
            LOGGER.info("Supported cipher suites: {}", supportedCipherSuites);
            LOGGER.info("Default cipher suites: {}", defaultCipherSuites);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Failed to get supported cipher suites", e);
        }

        return base;
    }
}
