package org.jboss.pnc.buildagent.client;

import org.jboss.logging.Logger;
import org.jboss.pnc.buildagent.common.StringUtils;
import org.jboss.pnc.buildagent.common.http.HttpClient;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public abstract class BuildAgentClientBase implements Closeable {

    private final Logger log = Logger.getLogger(BuildAgentClientBase.class);

    private final Optional<HttpClient> internalHttpClient;
    private final Optional<HttpClient> httpClient;
    protected final URI livenessProbeLocation;
    private final long livenessResponseTimeout;

    public BuildAgentClientBase(String termBaseUrl, long livenessResponseTimeout) throws BuildAgentClientException {
        this.livenessResponseTimeout = livenessResponseTimeout;
        termBaseUrl = StringUtils.stripEndingSlash(termBaseUrl);
        this.livenessProbeLocation = URI.create(termBaseUrl + "/servlet/is-alive");
        try {
            internalHttpClient = Optional.of(new HttpClient());
            httpClient = Optional.empty();
        } catch (IOException e) {
            throw new BuildAgentClientException("Cannot initialize http client.", e);
        }
    }

    /**
     * It is preferable to use a single instance of a HttpClient for all the BuildAgentClients because of the HttpClient's
     * internal thread pool.
     *
     * @param httpClient
     * @param termBaseUrl
     * @param livenessResponseTimeout
     */
    public BuildAgentClientBase(HttpClient httpClient, String termBaseUrl, long livenessResponseTimeout) {
        this.livenessResponseTimeout = livenessResponseTimeout;
        termBaseUrl = StringUtils.stripEndingSlash(termBaseUrl);
        this.livenessProbeLocation = URI.create(termBaseUrl + "/servlet/is-alive");
        this.internalHttpClient = Optional.empty();
        this.httpClient = Optional.of(httpClient);
    }

    public boolean isServerAlive() {
        CompletableFuture<HttpClient.Response> responseFuture = new CompletableFuture<>();
        getHttpClient().invoke(livenessProbeLocation, "HEAD", "", responseFuture);
        try {
            HttpClient.Response response = responseFuture.get(livenessResponseTimeout, TimeUnit.MILLISECONDS);
            boolean isSuccess = response.getCode() == 200;
            return isSuccess;
        } catch (InterruptedException | TimeoutException | ExecutionException e) {
            log.warn("Did not receive liveness probe response.", e);
            responseFuture.cancel(true);
            return false;
        }
    }

    protected HttpClient getHttpClient() {
        if (internalHttpClient.isPresent()) {
            return internalHttpClient.get();
        } else {
            return httpClient.get();
        }
    }

    @Override
    public void close() throws IOException {
        if (internalHttpClient.isPresent()) {
            internalHttpClient.get().close();
        }
    }
}
