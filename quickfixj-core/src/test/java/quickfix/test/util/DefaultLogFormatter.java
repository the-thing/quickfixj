package quickfix.test.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

public final class DefaultLogFormatter extends Formatter {

    private static final DateTimeFormatter DEFAULT_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final Map<Long, String> threadNameById;

    public DefaultLogFormatter() {
        this.threadNameById = new HashMap<>();
    }

    private static void formatStackTrace(Throwable exception, StringBuilder out) {
        try (StringWriter sw = new StringWriter();
             PrintWriter pw = new PrintWriter(sw)) {
            exception.printStackTrace(pw);
            out.append(sw.getBuffer()).append('\n');
        } catch (IOException e) {
            out.append("Failed to format stack trace: ").append(e.getMessage());
        }
    }

    private static void shortenClassName(String className, StringBuilder dst) {
        int index = className.lastIndexOf('.');

        if (index == -1) {
            dst.append(className);
            return;
        }

        dst.append(className.charAt(0));

        for (int i = 1; i < index; i++) {
            char current = className.charAt(i);
            char previous = className.charAt(i - 1);

            if (current == '.') {
                dst.append('.');
            } else if (previous == '.') {
                dst.append(current);
            }
        }

        dst.append(className, index, className.length());
    }

    @Override
    public String format(LogRecord record) {
        StringBuilder out = new StringBuilder();
        out.append(DEFAULT_FORMATTER.format(Instant.ofEpochMilli(record.getMillis())));

        String threadName = getThreadName(record.getThreadID());
        out.append(" [").append(threadName).append(']');

        out.append(" ").append(record.getLevel().getLocalizedName());

        out.append(" ");
        shortenClassName(record.getSourceClassName(), out);

        if (record.getMessage() != null) {
            out.append(" - ");
            out.append(record.getMessage());
        }

        out.append('\n');

        Throwable exception = record.getThrown();

        if (exception != null) {
            out.append("Exception in thread \"").append(threadName).append("\" ").append(exception.getClass()).append(": ").append(exception.getMessage()).append('\n');
            formatStackTrace(exception, out);
        }

        return out.toString();
    }

    private String getThreadName(long threadId) {
        String threadName = threadNameById.get(threadId);

        if (threadName != null) {
            return threadName;
        }

        Map<Thread, StackTraceElement[]> allStackTraces = Thread.getAllStackTraces();

        for (Thread thread : allStackTraces.keySet()) {
            if (thread.getId() == threadId) {
                threadNameById.put(threadId, thread.getName());
                return thread.getName();
            }
        }

        return "UNKNOWN";
    }
}
