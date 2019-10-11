package org.jboss.pnc.buildagent.client;

import java.io.Closeable;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public interface BuildAgentClient extends Closeable {

    void execute(Object command) throws BuildAgentClientException;

    void cancel() throws BuildAgentClientException;

    String getSessionId();

    boolean isServerAlive();
}
