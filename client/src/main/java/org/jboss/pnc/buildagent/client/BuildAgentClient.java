package org.jboss.pnc.buildagent.client;

import java.io.Closeable;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.jboss.pnc.buildagent.common.http.HttpClient;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public interface BuildAgentClient extends Closeable {

    void execute(Object command) throws BuildAgentClientException;

    CompletableFuture<HttpClient.Response> uploadFile(ByteBuffer buffer, Path remoteFilePath);

    CompletableFuture<HttpClient.Response> downloadFile(Path remoteFilePath);

    CompletableFuture<HttpClient.Response> downloadFile(Path remoteFilePath, long maxDownloadSize);

    /**
     *
     * @param command
     * @param executeTimeout Total time to wait for a remote invocation. Note there can be multiple internal retries.
     * @param unit
     * @throws BuildAgentClientException
     */
    void execute(Object command, long executeTimeout, TimeUnit unit) throws BuildAgentClientException;

    CompletableFuture<String> executeAsync(Object command);

    void cancel() throws BuildAgentClientException;

    CompletableFuture<HttpClient.Response> cancel(String sessionId);

    String getSessionId();

    CompletableFuture<Set<String>> getRunningProcesses();

    boolean isServerAlive();
}
