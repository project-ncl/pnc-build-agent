package org.jboss.pnc.buildagent.client;

import static org.jboss.pnc.api.dto.Request.Method.GET;
import static org.jboss.pnc.api.dto.Request.Method.HEAD;
import static org.jboss.pnc.api.dto.Request.Method.PUT;
import static org.jboss.pnc.buildagent.api.Constants.FILE_DOWNLOAD_PATH;
import static org.jboss.pnc.buildagent.api.Constants.FILE_UPLOAD_PATH;
import static org.jboss.pnc.buildagent.api.Constants.RUNNING_PROCESSES;

import java.io.Closeable;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.jboss.logging.Logger;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.api.httpinvoke.RetryConfig;
import org.jboss.pnc.buildagent.common.StringUtils;
import org.jboss.pnc.buildagent.common.http.HttpClient;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public abstract class BuildAgentClientBase implements Closeable {

    private final Logger log = Logger.getLogger(BuildAgentClientBase.class);
    final ObjectMapper objectMapper = new ObjectMapper();

    private final Optional<HttpClient> internalHttpClient;
    private final Optional<HttpClient> httpClient;
    protected final URI livenessProbeLocation;
    private final long livenessResponseTimeout;
    protected final RetryConfig retryConfig;
    private final URL fileUploadUrl;
    private final URL fileDownloadUrl;
    private final URL processListUrl;
    protected final List<Request.Header> requestHeaders;

    public BuildAgentClientBase(
            String termBaseUrl,
            long livenessResponseTimeout,
            RetryConfig retryConfig,
            List<Request.Header> requestHeaders) throws BuildAgentClientException {
        this.livenessResponseTimeout = livenessResponseTimeout;
        this.retryConfig = retryConfig;
        if (requestHeaders == null) {
            this.requestHeaders = Collections.emptyList();
        } else {
            this.requestHeaders = requestHeaders;
        }
        termBaseUrl = StringUtils.stripEndingSlash(termBaseUrl);
        this.livenessProbeLocation = URI.create(termBaseUrl + "/servlet/is-alive");

        try {
            fileUploadUrl = new URL(termBaseUrl + FILE_UPLOAD_PATH);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid file upload url.", e);
        }

        try {
            fileDownloadUrl = new URL(termBaseUrl + FILE_DOWNLOAD_PATH);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid file download url.", e);
        }

        try {
            processListUrl = new URL(termBaseUrl + RUNNING_PROCESSES);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid process list url.", e);
        }

        try {
            internalHttpClient = Optional.of(new HttpClient());
            httpClient = Optional.empty();
        } catch (IOException e) {
            throw new BuildAgentClientException("Cannot initialize http client.", e);
        }
    }

    /**
     * It is preferable to use a single instance of a HttpClient for all the BuildAgentClients because of the
     * HttpClient's
     * internal thread pool.
     * 
     * @param httpClient
     * @param termBaseUrl
     * @param livenessResponseTimeout
     * @param requestHeaders
     */
    public BuildAgentClientBase(
            HttpClient httpClient,
            String termBaseUrl,
            long livenessResponseTimeout,
            RetryConfig retryConfig,
            List<Request.Header> requestHeaders)
            throws BuildAgentClientException {
        this.livenessResponseTimeout = livenessResponseTimeout;
        this.retryConfig = retryConfig;
        if (requestHeaders == null) {
            this.requestHeaders = Collections.emptyList();
        } else {
            this.requestHeaders = requestHeaders;
        }
        termBaseUrl = StringUtils.stripEndingSlash(termBaseUrl);
        this.livenessProbeLocation = URI.create(termBaseUrl + "/servlet/is-alive");
        this.internalHttpClient = Optional.empty();
        this.httpClient = Optional.of(httpClient);

        try {
            fileUploadUrl = new URL(termBaseUrl + FILE_UPLOAD_PATH);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid file upload url.", e);
        }

        try {
            fileDownloadUrl = new URL(termBaseUrl + FILE_DOWNLOAD_PATH);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid file download url.", e);
        }

        try {
            processListUrl = new URL(termBaseUrl + RUNNING_PROCESSES);
        } catch (MalformedURLException e) {
            throw new BuildAgentClientException("Invalid process list url.", e);
        }
    }

    public boolean isServerAlive() {
        CompletableFuture<HttpClient.Response> responseFuture = getHttpClient().invoke(
                new Request(HEAD, livenessProbeLocation, requestHeaders),
                "");
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

    public CompletableFuture<HttpClient.Response> uploadFile(
            ByteBuffer buffer,
            Path remoteFilePath) {
        return getUri(fileUploadUrl.toString() + remoteFilePath.toString())
                .thenCompose(
                        uri -> getHttpClient().invoke(
                                new Request(PUT, uri, requestHeaders),
                                buffer,
                                retryConfig.getMaxRetries(),
                                retryConfig.getWaitBeforeRetry(),
                                -1L,
                                0,
                                0));
    }

    public CompletableFuture<HttpClient.Response> downloadFile(
            Path remoteFilePath) {
        return downloadFile(remoteFilePath, -1L);
    }

    public CompletableFuture<HttpClient.Response> downloadFile(
            Path remoteFilePath,
            long maxDownloadSize) {
        return getUri(fileDownloadUrl + remoteFilePath.toString())
                .thenCompose(
                        uri -> getHttpClient().invoke(
                                new Request(GET, uri, requestHeaders),
                                ByteBuffer.allocate(0),
                                retryConfig.getMaxRetries(),
                                retryConfig.getWaitBeforeRetry(),
                                maxDownloadSize,
                                0,
                                0));
    }

    public CompletableFuture<Set<String>> getRunningProcesses() {
        return getUri(processListUrl.toString())
                .thenCompose(
                        uri -> getHttpClient().invoke(
                                new Request(GET, uri, requestHeaders),
                                ByteBuffer.allocate(0),
                                retryConfig.getMaxRetries(),
                                retryConfig.getWaitBeforeRetry(),
                                -1L,
                                0,
                                0))
                .thenApply(response -> {
                    if (response.getCode() == 200) {
                        TypeReference<Set<String>> typeRef = new TypeReference<Set<String>>() {
                        };
                        try {
                            return objectMapper.readValue(response.getStringResult().getString(), typeRef);
                        } catch (IOException e) {
                            throw new CompletionException(
                                    new BuildAgentClientException(
                                            "Cannot read running processes response.",
                                            e));
                        }
                    } else {
                        throw new CompletionException(
                                new BuildAgentClientException(
                                        "Cannot get running processes. Response code: " + response.getCode()));
                    }
                });
    }

    private CompletableFuture<URI> getUri(String uri) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return new URI(uri);
            } catch (URISyntaxException e) {
                throw new CompletionException(e);
            }
        });
    }

    @Override
    public void close() throws IOException {
        if (internalHttpClient.isPresent()) {
            internalHttpClient.get().close();
        }
    }
}
