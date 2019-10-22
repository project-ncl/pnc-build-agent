package org.jboss.pnc.buildagent.client;

import org.jboss.logging.Logger;
import org.jboss.pnc.buildagent.common.StringUtils;
import org.jboss.pnc.buildagent.common.http.HttpClient;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public abstract class BuildAgentClientBase {

    private final Logger log = Logger.getLogger(BuildAgentClientBase.class);

    protected final HttpClient httpClient;
    protected final URI livenessProbeLocation;

    public BuildAgentClientBase(String termBaseUrl) throws BuildAgentClientException {
        termBaseUrl = StringUtils.stripEndingSlash(termBaseUrl);
        this.livenessProbeLocation = URI.create(termBaseUrl + "/servlet/is-alive");
        try {
            httpClient = new HttpClient();
        } catch (IOException e) {
            throw new BuildAgentClientException("Cannot initialize http client.", e);
        }
    }

    public boolean isServerAlive() {
        CompletableFuture<HttpClient.Response> responseFuture = new CompletableFuture<>();
        httpClient.invoke(livenessProbeLocation, "HEAD", "", responseFuture);
        try {
            HttpClient.Response response = responseFuture.get(5, TimeUnit.SECONDS);
            return response.getCode() == 200;
        } catch (InterruptedException | TimeoutException | ExecutionException e) {
            log.warn("Did not receive liveness probe response.", e);
            return false;
        }
    }
}
