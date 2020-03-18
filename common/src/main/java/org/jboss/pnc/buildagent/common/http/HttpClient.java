package org.jboss.pnc.buildagent.common.http;

import io.undertow.client.ClientCallback;
import io.undertow.client.ClientConnection;
import io.undertow.client.ClientExchange;
import io.undertow.client.ClientRequest;
import io.undertow.client.UndertowClient;
import io.undertow.connector.ByteBufferPool;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.StringReadChannelListener;
import io.undertow.util.StringWriteChannelListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.Xnio;
import org.xnio.XnioWorker;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class HttpClient implements Closeable {
    private final Logger logger = LoggerFactory.getLogger(HttpClient.class);

    private final XnioWorker xnioWorker;

    private final ByteBufferPool buffer;

    private static final OptionMap DEFAULT_OPTIONS;

    static {
        final OptionMap.Builder builder = OptionMap.builder()
                .set(Options.WORKER_IO_THREADS, 8)
                .set(Options.TCP_NODELAY, true)
                .set(Options.KEEP_ALIVE, true)
                .set(Options.WORKER_NAME, "Build Agent Http Client");
        DEFAULT_OPTIONS = builder.getMap();
    }

    public HttpClient() throws IOException {
        final Xnio xnio = Xnio.getInstance();
        xnioWorker = xnio.createWorker(null, DEFAULT_OPTIONS);

        buffer = new DefaultByteBufferPool(
                true,
                1024 * 16,
                1000,
                10,
                100);
    }

    public HttpClient(XnioWorker xnioWorker, ByteBufferPool buffer) throws IOException {
        final Xnio xnio = Xnio.getInstance();
        this.xnioWorker = xnioWorker;
        this.buffer = buffer;
    }

    public void invoke(URI uri, String requestMethod, String data, CompletableFuture<Response> responseFuture) {
        logger.trace("Making {} request to the endpoint {}; request data: {}.", requestMethod, uri.toString(), data);

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

        CompletableFuture<String> onResponseCompletedFuture = new CompletableFuture<>();
        Function<ByteBufferPool, StringReadChannelListener> stringReadChannelListener = (bufferPool) ->
            new StringReadChannelListener(bufferPool) {
                @Override
                protected void stringDone(String string) {
                    onResponseCompletedFuture.complete(string);
                }
                @Override
                protected void error(IOException e) {
                    onResponseCompletedFuture.completeExceptionally(e);
                }
        };

        Response response = new Response();

        undertowClient.connect(clientConnection, uri, xnioWorker, buffer, DEFAULT_OPTIONS);
        clientConnectionFuture.thenCompose(connection -> {
                ClientRequest request = new ClientRequest();
                request.setMethod(HttpString.tryFromString(requestMethod));
                request.setPath(uri.getPath());
                request.getRequestHeaders().put(Headers.HOST, "localhost");
                request.getRequestHeaders().put(Headers.TRANSFER_ENCODING, "chunked");

                connection.sendRequest(request, onRequestStart);
                return onRequestStartFuture;
            }
        ).thenCompose(exchange -> {
                new StringWriteChannelListener(data).setup(exchange.getRequestChannel());
                exchange.setResponseListener(onResponseStarted);
                return onResponseStartedFuture;
            }
        ).thenCompose(exchange -> {
                response.code = exchange.getResponse().getResponseCode();
                stringReadChannelListener.apply(buffer).setup(exchange.getResponseChannel());
                return onResponseCompletedFuture;
            }
        ).handle((string, throwable) -> {
            if (throwable != null) {
                logger.error("Error: ", throwable);
                responseFuture.completeExceptionally(throwable);
            }
            response.string = string;
            responseFuture.complete(response);
            return null;
        });
    }

    @Override
    public void close() throws IOException {
        xnioWorker.shutdown();
    }

    public static class Response {
        private int code;
        private String string;

        public int getCode() {
            return code;
        }

        public String getString() {
            return string;
        }
    }
}
