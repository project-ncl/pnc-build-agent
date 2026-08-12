package org.jboss.pnc.buildagent.server.logging.performance;

import java.time.Duration;
import java.util.function.Consumer;

import org.jboss.pnc.buildagent.server.QueueAdapter;

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
