package org.jboss.pnc.buildagent.server.logging.formatters.jboss;

import java.io.IOException;
import java.util.Properties;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.jboss.logmanager.LogContext;
import org.jboss.logmanager.LogManager;
import org.jboss.logmanager.PropertyConfigurator;
import org.jboss.pnc.buildagent.api.logging.LogFormatter;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class JBossFormatter implements LogFormatter {

    Formatter formatter;

    public JBossFormatter() throws InstantiationException {
        LogManager logManager;
        try {
            logManager = (LogManager) LogManager.getLogManager();
        } catch (ClassCastException e) {
            throw new InstantiationException(
                    "Make sure the system property '-Djava.util.logging.manager=org.jboss.logmanager.LogManager' is set: "
                            + e.getMessage());
        }

        Logger rootLogger = logManager.getLogger("");
        init(rootLogger);
    }

    public JBossFormatter(Properties config) throws InstantiationException {
        LogContext logContext = LogContext.create(false);
        PropertyConfigurator configurator = new PropertyConfigurator(logContext);
        try {
            configurator.configure(config);
        } catch (IOException e) {
            throw new InstantiationException("Cannot configure JBossFormatter: " + e.getMessage());
        }

        Logger rootLogger = logContext.getLogger("");
        init(rootLogger);
    }

    private void init(Logger rootLogger) throws InstantiationException {
        Handler[] handlers = rootLogger.getHandlers();

        for (Handler handler : handlers) {
            if (handler instanceof FormatterReference) {
                formatter = handler.getFormatter();
            }
        }
        if (formatter == null) {
            throw new InstantiationException(
                    "Missing JsonFormatter configuration. Add 'handler.FORMATTER_REF=org.jboss.pnc.buildagent.server.logging.formatters.jboss.FormatterReference' with a reference to the formatter.");
        }
    }

    @Override
    public String format(String message) {
        LogRecord record = new LogRecord(Level.INFO, message);
        record.setLoggerName("org.jboss.pnc._userlog_.build-log");
        record.setMillis(System.currentTimeMillis());
        return formatter.format(record);
    }
}
