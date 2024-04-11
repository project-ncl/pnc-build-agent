package org.jboss.pnc.buildagent.common.http;

import io.undertow.client.ClientCallback;
import io.undertow.client.ClientConnection;
import io.undertow.client.ClientExchange;
import io.undertow.client.ClientRequest;
import io.undertow.client.UndertowClient;
import io.undertow.connector.ByteBufferPool;
import io.undertow.protocols.ssl.UndertowXnioSsl;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.common.BuildAgentException;
import org.jboss.pnc.buildagent.common.concurrent.MDCScheduledThreadPoolExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.Xnio;
import org.xnio.XnioWorker;
import org.xnio.channels.StreamSinkChannel;

import javax.net.ssl.SSLContext;
import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class HttpClient implements Closeable {
    private final Logger logger = LoggerFactory.getLogger(HttpClient.class);

    private final XnioWorker xnioWorker;

    private final ByteBufferPool buffer;
    private final UndertowXnioSsl undertowXnioSsl;

    public final OptionMap options;
    public static final OptionMap DEFAULT_OPTIONS;

    public static int DEFAULT_HTTP_WRITE = 30000;
    public static int DEFAULT_HTTP_READ = 30000;

    private ScheduledExecutorService executor = new MDCScheduledThreadPoolExecutor(4);

    static {
        final OptionMap.Builder builder = OptionMap.builder()
                .set(Options.WORKER_IO_THREADS, 8)
                .set(Options.TCP_NODELAY, true)
                .set(Options.KEEP_ALIVE, true)
                .set(Options.WORKER_NAME, "Build Agent Http Client")
                .set(Options.READ_TIMEOUT, DEFAULT_HTTP_READ)
                .set(Options.WRITE_TIMEOUT, DEFAULT_HTTP_WRITE);
        DEFAULT_OPTIONS = builder.getMap();
    }

    public HttpClient() throws IOException {
        this(DEFAULT_OPTIONS);
    }

    public HttpClient(int httpReadTimeout, int httpWriteTimeout) throws IOException {
        this(OptionMap.builder()
            .addAll(DEFAULT_OPTIONS)
            .set(Options.READ_TIMEOUT, httpReadTimeout)
            .set(Options.WRITE_TIMEOUT, httpWriteTimeout)
            .getMap());
    }

    public HttpClient(OptionMap options) throws IOException{
        this(Xnio.getInstance().createWorker(null, options),
            new DefaultByteBufferPool(
                true,
                1024 * 16,
                1000,
                10,
                100),
            options);
    }

    public HttpClient(XnioWorker xnioWorker, ByteBufferPool buffer) throws IOException {
        this(xnioWorker, buffer, DEFAULT_OPTIONS);
    }

    public HttpClient(XnioWorker xnioWorker, ByteBufferPool buffer, OptionMap options) throws IOException {
        this.xnioWorker = xnioWorker;
        this.buffer = buffer;
        this.options = options;
        try {
            undertowXnioSsl = new UndertowXnioSsl(xnioWorker.getXnio(), options, SSLContext.getDefault());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public CompletableFuture<Response> invoke(Request request, String data) {
        logger.debug("Making {} request to the endpoint {}.", request.getMethod(), request.getUri());
        if (logger.isTraceEnabled()) {
            logger.trace("Making {} request to the endpoint {}; request data: {}.", request.getMethod(), request.getUri(), data);
        }
        return invoke(request, ByteBuffer.wrap(data.getBytes(UTF_8)), 0, 0L, -1L, 0, 0);
    }

    /**
     *
     * @param request
     * @param data
     * @param maxRetries
     * @param waitBeforeRetry milliseconds
     * @param maxDownloadSize bytes, -1 disabled
     * @param readTimeout milliseconds between read bytes, 0 for disabled
     * @param writeTimeout milliseconds between written bytes, 0 for disabled
     * @return
     */
    public CompletableFuture<Response> invoke(
            Request request,
            ByteBuffer data,
            int maxRetries,
            long waitBeforeRetry,
            long maxDownloadSize,
            int readTimeout,
            int writeTimeout) {
        logger.info("Making request {} {}; Headers: {}.", request.getMethod(), request.getUri(), request.getHeaders());
        if (data != null && logger.isTraceEnabled()) {
            logger.trace("Making request {} {}; Headers: {} request data: {}.", request.getMethod(), request.getUri(), request.getHeaders(), StandardCharsets.UTF_8.decode(data).toString());
            data.rewind();
        }

        CompletableFuture<Response> responseFuture = new CompletableFuture<>();
        invokeAttempt(request.getUri(), request.getMethod(), request.getHeaders(), data, responseFuture, 0, maxRetries, waitBeforeRetry, maxDownloadSize, readTimeout, writeTimeout);
        return responseFuture;
    }

    /**
     *
     * @param uri
     * @param requestMethod
     * @param requestHeaders
     * @param data
     * @param responseFuture
     * @param attempt
     * @param maxRetries
     * @param waitBeforeRetry Wait before retry is calculated as attempt * waitBeforeRetry[millis].
     */
    private void invokeAttempt(
            URI uri,
            Request.Method requestMethod,
            List<Request.Header> requestHeaders,
            ByteBuffer data,
            CompletableFuture<Response> responseFuture,
            int attempt,
            int maxRetries,
            long waitBeforeRetry,
            long maxDownloadSize,
            int readTimeout,
            int writeTimeout) {
        if (attempt > 0) {
            logger.warn(
                    "Retrying ({}) {} request to the endpoint {}.",
                    attempt,
                    requestMethod,
                    uri.toString());
            if (data != null && logger.isTraceEnabled()) {
                logger.trace(
                        "Retrying ({}) {} request to the endpoint {}; request data: {}.",
                        attempt,
                        requestMethod,
                        uri.toString(),
                        StandardCharsets.UTF_8.decode(data).toString());
                data.rewind();
            }
        }

        UndertowClient undertowClient = UndertowClient.getInstance();

        //see https://github.com/undertow-io/undertow/blob/master/core/src/test/java/io/undertow/client/http/HttpClientTestCase.java
        CompletableFuture<ClientConnection> clientConnectionFuture = new CompletableFuture<>();
        ClientCallback<ClientConnection> clientConnection = new ClientCallback<ClientConnection>() {
            @Override
            public void completed(ClientConnection connection) {
                clientConnectionFuture.complete(connection);
            }
            @Override
            public void failed(IOException e) {
                clientConnectionFuture.completeExceptionally(e);
            }
        };

        CompletableFuture<ClientExchange> onRequestStartFuture = new CompletableFuture<>();
        ClientCallback<ClientExchange> onRequestStart = new ClientCallback<ClientExchange>() {
            @Override
            public void completed(ClientExchange exchange) {
                onRequestStartFuture.complete(exchange);
            }
            @Override
            public void failed(IOException e) {
                onRequestStartFuture.completeExceptionally(e);
            }
        };

        CompletableFuture<ClientExchange> onResponseStartedFuture = new CompletableFuture<>();
        ClientCallback<ClientExchange> onResponseStarted = new ClientCallback<ClientExchange>() {
            @Override
            public void completed(ClientExchange exchange) {
                onResponseStartedFuture.complete(exchange);
            }
            @Override
            public void failed(IOException e) {
                onResponseStartedFuture.completeExceptionally(e);
            }
        };

        CompletableFuture<StringResult> onResponseCompletedFuture = new CompletableFuture<>();
        Function<ByteBufferPool, LimitingStringReadChannelListener> stringReadChannelListener = (bufferPool) ->
            new LimitingStringReadChannelListener(bufferPool, maxDownloadSize) {
                @Override
                protected void stringDone(StringResult result) {
                    onResponseCompletedFuture.complete(result);
                }
                @Override
                protected void error(IOException e) {
                    onResponseCompletedFuture.completeExceptionally(e);
                }
        };

        Response response = new Response();

        CompletableFuture.completedFuture(null).thenCompose(nul -> {
                undertowClient.connect(clientConnection, uri, xnioWorker, undertowXnioSsl, buffer, options);
                return clientConnectionFuture;
            }
        ).thenCompose(connection -> {
                ClientRequest request = new ClientRequest();
                request.setMethod(HttpString.tryFromString(requestMethod.name()));
                request.setPath(uri.getPath());
                request.getRequestHeaders().put(Headers.HOST, uri.getHost());
                request.getRequestHeaders().put(Headers.TRANSFER_ENCODING, "chunked");
                requestHeaders.forEach((header) -> request.getRequestHeaders()
                        .put(new HttpString(header.getName()), header.getValue()));
                connection.sendRequest(request, onRequestStart);
                return onRequestStartFuture;
            }
        ).thenCompose(exchange -> {
            StreamSinkChannel requestChannel = exchange.getRequestChannel();
            try {
                if (readTimeout > 0) {
                    requestChannel.setOption(Options.READ_TIMEOUT, readTimeout);
                }
                if (writeTimeout > 0) {
                    requestChannel.setOption(Options.WRITE_TIMEOUT, writeTimeout);
                }
            } catch (IOException e) {
                throw new CompletionException(new BuildAgentException("Cannot set request timeout.", e));
            }
            new ByteBufferWriteChannelListener(data).setup(requestChannel);
            exchange.setResponseListener(onResponseStarted);
                return onResponseStartedFuture;
            }
        ).thenCompose(exchange -> {
                response.code = exchange.getResponse().getResponseCode();
                //retry if 503 Service Unavailable or 504 Gateway Timeout
                if (response.getCode() == 503 || response.getCode() == 504) {
                    onResponseCompletedFuture.completeExceptionally(
                            new RuntimeException("Received response code: " + response.getCode()));
                } else {
                    stringReadChannelListener.apply(buffer).setup(exchange.getResponseChannel());
                }
                return onResponseCompletedFuture;
            }
        ).handle((stringResult, throwable) -> {
            if (throwable != null) {
                logger.error("Error: ", throwable);
                if (maxRetries > 0 && attempt < maxRetries) {
                    data.rewind();
                    executor.schedule(
                            () -> invokeAttempt(
                                    uri,
                                    requestMethod,
                                    requestHeaders,
                                    data,
                                    responseFuture,
                                    attempt + 1,
                                    maxRetries,
                                    waitBeforeRetry,
                                    maxDownloadSize,
                                    readTimeout,
                                    writeTimeout),
                            waitBeforeRetry * attempt, TimeUnit.MILLISECONDS
                    );
                } else {
                    logger.info("Invocation completed exceptionally. Response code: " + response.getCode());
                    responseFuture.completeExceptionally(throwable);
                }
            } else {
                response.stringResult = stringResult;
                logger.info("Invocation completed. Response code: " + response.getCode());
                responseFuture.complete(response);
            }
            return null;
        });
    }

    @Override
    public void close() throws IOException {
        logger.info("Shutting down.");
        executor.shutdownNow();
        xnioWorker.shutdown();
    }

    public static class Response {
        private int code;
        private StringResult stringResult;

        public Response() {
        }

        public Response(int code, StringResult stringResult) {
            this.code = code;
            this.stringResult = stringResult;
        }

        public int getCode() {
            return code;
        }

        public StringResult getStringResult() {
            return stringResult;
        }
    }
}
