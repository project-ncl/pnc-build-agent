package org.jboss.pnc.buildagent.server.logging.performance;

import org.jboss.pnc.buildagent.server.QueueAdapter;

import java.time.Duration;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class NoOpQueueAdapter implements QueueAdapter {

    @Override
    public void flush() {

    }

    @Override
    public void send(String message, Consumer<Exception> exceptionHandler) {

    }

    @Override
    public void close(Duration duration) {

    }

    @Override
    public void close() {

    }
}
