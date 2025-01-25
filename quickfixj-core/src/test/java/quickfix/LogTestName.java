package quickfix;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class LogTestName implements TestRule {

    private static final Logger LOGGER = LoggerFactory.getLogger("LogTestName.");

    @Override
    public Statement apply(Statement base, Description description) {
        LOGGER.info("{} [{}] Running test '{}#{}'",  System.currentTimeMillis(), Thread.currentThread(), description.getClassName(), description.getMethodName());
        return base;
    }
}
