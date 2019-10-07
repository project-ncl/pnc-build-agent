package org.jboss.pnc.buildagent.server;

import java.time.Duration;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public interface QueueAdapter {

    void flush();

    void send(String message, Consumer<Exception> exceptionHandler);

    void close(Duration duration);

    void close();

}
