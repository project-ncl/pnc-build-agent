package org.jboss.pnc.buildagent.client;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.jboss.pnc.api.dto.HeartbeatConfig;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.api.Constants;
import org.jboss.pnc.buildagent.api.httpinvoke.Cancel;
import org.jboss.pnc.buildagent.api.httpinvoke.InvokeRequest;
import org.jboss.pnc.buildagent.api.httpinvoke.InvokeResponse;
import org.jboss.pnc.buildagent.api.httpinvoke.RetryConfig;
import org.jboss.pnc.buildagent.common.StringUtils;
import org.jboss.pnc.buildagent.common.http.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class BuildAgentHttpClient extends BuildAgentClientBase implements BuildAgentClient {
    private final Logger logger = LoggerFactory.getLogger(BuildAgentHttpClient.class);

    private final URI invokerUri;

    private final Request callback;

    private final Optional<HeartbeatConfig> heartbeatConfig;

    private String sessionId;

    /**
     * @see BuildAgentHttpClient( HttpClientConfiguration )
     */
    @Deprecated
    public BuildAgentHttpClient(String termBaseUrl, URL callbackUrl, String callbackMethod)
            throws BuildAgentClientException {
        super(termBaseUrl, 30000, new RetryConfig(10, 500), Collections.emptyList());
        try {
            this.callback = new Request(
                    Request.Method.valueOf(callbackMethod),
                    callbackUrl.toURI(),
                    Collections.emptyList());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        this.heartbeatConfig = Optional.empty();
        try {
            invokerUri = new URI(termBaseUrl + Constants.HTTP_INVOKER_FULL_PATH);
        } catch (URISyntaxException e) {
            throw new BuildAgentClientException("Invalid term url.", e);
        }
    }

    public BuildAgentHttpClient(HttpClientConfiguration configuration)
            throws BuildAgentClientException {
        super(
                configuration.getTermBaseUrl(),
                configuration.getLivenessResponseTimeout(),
                configuration.getRetryConfig(),
                configuration.getRequestHeaders());
        this.callback = configuration.getCallback();
        this.heartbeatConfig = configuration.getHeartbeatConfig();
        try {
            String agentBaseUrl = StringUtils.stripEndingSlash(configuration.getTermBaseUrl());
            invokerUri = new URI(agentBaseUrl + Constants.HTTP_INVOKER_FULL_PATH);
        } catch (URISyntaxException e) {
            throw new BuildAgentClientException("Invalid term url.", e);
        }
    }

    /**
     * It is preferable to use a single instance of a HttpClient for all the BuildAgentClients because of the
     * HttpClient's
     * internal thread pool.
     */
    public BuildAgentHttpClient(HttpClient httpClient, HttpClientConfiguration configuration)
            throws BuildAgentClientException {
        super(
                httpClient,
                configuration.getTermBaseUrl(),
                configuration.getLivenessResponseTimeout(),
                configuration.getRetryConfig(),
                configuration.getRequestHeaders());
        this.callback = configuration.getCallback();
        this.heartbeatConfig = configuration.getHeartbeatConfig();
        try {
            String agentBaseUrl = StringUtils.stripEndingSlash(configuration.getTermBaseUrl());
            invokerUri = new URI(agentBaseUrl + Constants.HTTP_INVOKER_FULL_PATH);
        } catch (URISyntaxException e) {
            throw new BuildAgentClientException("Invalid term url.", e);
        }
    }

    @Override
    public void execute(Object command) throws BuildAgentClientException {
        execute(command, 10, TimeUnit.SECONDS);
    }

    @Override
    public void execute(Object command, long executeTimeout, TimeUnit unit) throws BuildAgentClientException {
        CompletableFuture<HttpClient.Response> responseFuture = internalExecuteAsync(command, heartbeatConfig);

        HttpClient.Response response;
        try {
            response = responseFuture.get(executeTimeout, unit);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            logger.error("No response from the remote agent.", e);
            throw new BuildAgentClientException("No response from the remote agent.", e);
        }
        try {
            sessionId = parseSessionID(response);
        } catch (IOException e) {
            throw new BuildAgentClientException("Cannot read command invocation response.", e);
        }
    }

    @Override
    public CompletableFuture<String> executeAsync(Object command) {
        return internalExecuteAsync(command, this.heartbeatConfig)
                .thenApply(response -> {
                    try {
                        return parseSessionID(response);
                    } catch (IOException e) {
                        throw new CompletionException(
                                new BuildAgentClientException("Cannot read command invocation response.", e));
                    }
                });
    }

    private String parseSessionID(HttpClient.Response response) throws IOException {
        logger.debug("Response code: {}, body: {}.", response.getCode(), response.getStringResult().getString());
        InvokeResponse invokeResponse = objectMapper
                .readValue(response.getStringResult().getString(), InvokeResponse.class);
        return invokeResponse.getSessionId();
    }

    private CompletableFuture<HttpClient.Response> internalExecuteAsync(
            Object command,
            Optional<HeartbeatConfig> heartbeatConfig) {
        String cmd;
        if (command instanceof String) {
            cmd = (String) command;
        } else {
            CompletableFuture<HttpClient.Response> result = new CompletableFuture<>();
            result.completeExceptionally(new BuildAgentClientException("Http client supports only String commands."));
            return result;
        }

        return asJson(new InvokeRequest(cmd, this.callback, heartbeatConfig.orElse(null)))
                .thenCompose(requestJson -> {
                    return getHttpClient().invoke(
                            new Request(Request.Method.POST, invokerUri, requestHeaders),
                            ByteBuffer.wrap(requestJson.getBytes(StandardCharsets.UTF_8)),
                            retryConfig.getMaxRetries(),
                            retryConfig.getWaitBeforeRetry(),
                            1L,
                            0,
                            0);
                });
    }

    /**
     *
     * @return true if cancel was successful
     * @throws BuildAgentClientException
     */
    @Override
    public void cancel() throws BuildAgentClientException {
        CompletableFuture<HttpClient.Response> responseFuture = cancel(sessionId);
        try {
            HttpClient.Response response = responseFuture.get(5, TimeUnit.SECONDS);
            if (response.getCode() != 200) {
                throw new BuildAgentClientException(
                        String.format("Remove invocation failed, received status {}.", response.getCode()));
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            throw new BuildAgentClientException("Error reading cancel request.", e);
        }
    }

    @Override
    public CompletableFuture<HttpClient.Response> cancel(String sessionId) {
        return asJson(new Cancel(sessionId))
                .thenCompose(
                        requestJson -> getHttpClient().invoke(
                                new Request(Request.Method.PUT, invokerUri, requestHeaders),
                                ByteBuffer.wrap(requestJson.getBytes(StandardCharsets.UTF_8)),
                                retryConfig.getMaxRetries(),
                                retryConfig.getWaitBeforeRetry(),
                                -1L,
                                0,
                                0));
    }

    private CompletableFuture<String> asJson(Object request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return objectMapper.writeValueAsString(request);
            } catch (JsonProcessingException e) {
                throw new CompletionException(new BuildAgentClientException("Cannot serialize request object.", e));
            }
        });
    }

    @Override
    public String getSessionId() {
        return sessionId;
    }
}
