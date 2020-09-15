package org.jboss.pnc.buildagent.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.pnc.buildagent.api.Constants;
import org.jboss.pnc.buildagent.api.httpinvoke.Cancel;
import org.jboss.pnc.buildagent.api.httpinvoke.InvokeRequest;
import org.jboss.pnc.buildagent.api.httpinvoke.InvokeResponse;
import org.jboss.pnc.buildagent.common.http.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class BuildAgentHttpClient extends BuildAgentClientBase implements BuildAgentClient {
    private final Logger logger = LoggerFactory.getLogger(BuildAgentHttpClient.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final URL invokerUrl;

    private final URL callbackUrl;

    private final String callbackMethod;

    private String sessionId;

    /**
     * @see BuildAgentHttpClient( HttpClientConfiguration )
     */
    @Deprecated
    public BuildAgentHttpClient(String termBaseUrl, URL callbackUrl, String callbackMethod)
            throws BuildAgentClientException {
        super(termBaseUrl, 30000);
        this.callbackUrl = callbackUrl;
        this.callbackMethod = callbackMethod;
        try {
            invokerUrl = new URL(termBaseUrl + Constants.HTTP_INVOKER_FULL_PATH);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid term url.", e);
        }
    }

    public BuildAgentHttpClient(HttpClientConfiguration configuration)
            throws BuildAgentClientException {
        super(configuration.getTermBaseUrl(), configuration.getLivenessResponseTimeout());
        this.callbackUrl = configuration.getCallbackUrl();
        this.callbackMethod = configuration.getCallbackMethod();
        try {
            invokerUrl = new URL(configuration.getTermBaseUrl() + Constants.HTTP_INVOKER_FULL_PATH);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid term url.", e);
        }
    }

    /**
     * It is preferable to use a single instance of a HttpClient for all the BuildAgentClients because of the HttpClient's
     * internal thread pool.
     */
    public BuildAgentHttpClient(HttpClient httpClient, HttpClientConfiguration configuration)
            throws BuildAgentClientException {
        super(httpClient, configuration.getTermBaseUrl(), configuration.getLivenessResponseTimeout());
        this.callbackUrl = configuration.getCallbackUrl();
        this.callbackMethod = configuration.getCallbackMethod();
        try {
            invokerUrl = new URL(configuration.getTermBaseUrl() + Constants.HTTP_INVOKER_FULL_PATH);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid term url.", e);
        }
    }

    @Override
    public void execute(Object command) throws BuildAgentClientException {
        String cmd;
        if (command instanceof String) {
            cmd = (String) command;
        } else {
            throw new BuildAgentClientException("Http client supports only String commands.");
        }

        InvokeRequest request = new InvokeRequest(cmd, callbackUrl, callbackMethod);
        CompletableFuture<HttpClient.Response> responseFuture = new CompletableFuture<>();
        try {
            String requestJson = objectMapper.writeValueAsString(request);
            getHttpClient().invoke(invokerUrl.toURI(), "POST", requestJson, responseFuture);
        } catch (JsonProcessingException e) {
            throw new BuildAgentClientException("Cannot serialize request.", e);
        } catch (URISyntaxException e) {
            throw new BuildAgentClientException("Invalid command execution url.", e);
        }
        HttpClient.Response response = null; //TODO timeout
        try {
            response = responseFuture.get(5, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            throw new BuildAgentClientException("No response form the remote agent.", e);
        }
        InvokeResponse invokeResponse;
        try {
            invokeResponse = objectMapper.readValue(response.getString(), InvokeResponse.class);
        } catch (IOException e) {
            throw new BuildAgentClientException("Cannot read command invocation response.", e);
        }
        sessionId = invokeResponse.getSessionId();
    }

    /**
     *
     * @return true if cancel was successful
     * @throws BuildAgentClientException
     */
    @Override
    public void cancel() throws BuildAgentClientException {
        Cancel request = new Cancel(sessionId);
        CompletableFuture<HttpClient.Response> responseFuture = new CompletableFuture<>();
        try {
            String requestJson = objectMapper.writeValueAsString(request);
            getHttpClient().invoke(invokerUrl.toURI(), "PUT", requestJson, responseFuture);
        } catch (JsonProcessingException e) {
            throw new BuildAgentClientException("Cannot serialize cancel request.", e);
        } catch (IOException e) {
            throw new BuildAgentClientException("Cannot invoke cancel.", e);
        } catch (URISyntaxException e) {
            throw new BuildAgentClientException("Invalid cancel url.", e);
        }
        try {
            HttpClient.Response response = responseFuture.get(5, TimeUnit.SECONDS);
            if (response.getCode() != 200) {
                throw new BuildAgentClientException(String.format("Remove invocation failed, received status {}.", response.getCode()));
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            throw new BuildAgentClientException("Error reading cancel request.", e);
        }
    }

    @Override
    public String getSessionId() {
        return sessionId;
    }
}
