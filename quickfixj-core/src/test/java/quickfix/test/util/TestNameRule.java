package quickfix.test.util;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class TestNameRule implements TestRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestNameRule.class);

    private String testName;

    @Override
    public Statement apply(Statement base, Description description) {
        testName = description.getTestClass().getName() + '#' + description.getMethodName();
        LOGGER.info("Running test '{}'", testName);
        return base;
    }

    public String getTestName() {
        return testName;
    }
}
