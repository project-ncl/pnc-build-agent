package org.jboss.pnc.buildagent.common;

import static org.jboss.pnc.buildagent.common.http.HttpClient.DEFAULT_OPTIONS;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.common.http.HttpClient;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xnio.Xnio;
import org.xnio.XnioWorker;
import org.xnio.channels.StreamSinkChannel;

import io.undertow.Undertow;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.server.HttpHandler;

public class HttpClientTest {

    private static final Logger logger = LoggerFactory.getLogger(HttpClientTest.class);

    @BeforeClass
    public static void setup() {

    }

    @Test
    @Ignore //not a real test case, inspect the log
    public void shouldRetryFailedConnection()
            throws IOException, ExecutionException, InterruptedException, URISyntaxException {
        HttpClient httpClient = new HttpClient();
        CompletableFuture<HttpClient.Response> completableFuture = httpClient
                .invoke(new Request(Request.Method.GET, new URI("http://host-not-found/")), "");
        completableFuture.get();
    }

    @Test(timeout = 5000L)
    public void shouldLimitDownloadSize()
            throws IOException, ExecutionException, InterruptedException, URISyntaxException {
        HttpHandler handler = exchange -> {
            StreamSinkChannel responseChannel = exchange.getResponseChannel();
            for (int i = 0; i < 1000; i++) {
                responseChannel.write(ByteBuffer.wrap(UUID.randomUUID().toString().getBytes()));
            }
            responseChannel.writeFinal(ByteBuffer.wrap(UUID.randomUUID().toString().getBytes()));
            logger.info("Done test limit response.");
        };
        Undertow undertow = Undertow.builder()
                .addHttpListener(8080, "localhost")
                .setHandler(handler)
                .build();
        undertow.start();

        HttpClient httpClient = null;
        final Xnio xnio = Xnio.getInstance();
        XnioWorker xnioWorker = xnio.createWorker(null, DEFAULT_OPTIONS);
        DefaultByteBufferPool bufferPool = new DefaultByteBufferPool(false, 1024, 10, 10, 100);
        try {
            httpClient = new HttpClient(xnioWorker, bufferPool);
            CompletableFuture<HttpClient.Response> responseFuture = httpClient.invoke(
                    new Request(Request.Method.GET, new URI("http://localhost:8080/")),
                    ByteBuffer.allocate(0),
                    0,
                    0,
                    1024,
                    0,
                    0);
            HttpClient.Response response = responseFuture.get();
            Assert.assertFalse("Should be uncompleted response.", response.getStringResult().isComplete());
            Assert.assertTrue("Download limit exceeded.", response.getStringResult().getString().length() < 2 * 1024); //limit + buffer size
        } finally {
            bufferPool.close();
            httpClient.close();
            undertow.stop();
        }
    }
}
