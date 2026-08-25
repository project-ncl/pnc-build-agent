package org.jboss.pnc.buildagent.server.httpinvoker;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import javax.servlet.ServletException;

import org.jboss.pnc.api.dto.HeartbeatConfig;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.api.Status;
import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.jboss.pnc.buildagent.client.BuildAgentClient;
import org.jboss.pnc.buildagent.client.BuildAgentClientException;
import org.jboss.pnc.buildagent.client.BuildAgentHttpClient;
import org.jboss.pnc.buildagent.client.HttpClientConfiguration;
import org.jboss.pnc.buildagent.server.TermdServer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class TestCommandExecution {
    private static final Logger log = LoggerFactory.getLogger(TestCommandExecution.class);

    private static Set<Consumer<String>> responseConsumers = new HashSet<>();
    private static AtomicInteger heartbeatCounter = new AtomicInteger();

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final String HOST = "localhost";
    private static final int PORT = TermdServer.getNextPort();
    private static final int LOCAL_PORT = TermdServer.getNextPort();
    private static final String TEST_COMMAND_BASE = "java -cp ./server/target/test-classes/:./target/test-classes/ org.jboss.pnc.buildagent.server.MockProcess ";

    String terminalBaseUrl = "http://" + HOST + ":" + PORT;

    private static HttpServer callbackServer;

    @BeforeClass
    public static void setUP() throws Exception {
        TermdServer.startServer(HOST, PORT, "", false, false);

        callbackServer = new HttpServer();

        Consumer<String> responseConsumer = (s) -> responseConsumers.forEach(rc -> rc.accept(s));
        ResponseConsumerAddindServletFactory callbackHandlerFactory = new ResponseConsumerAddindServletFactory(
                responseConsumer);
        HeartbeatServletFactory heartbeatServletFactory = new HeartbeatServletFactory(heartbeatCounter);
        callbackServer.addServlet(CallbackHandler.class, Optional.of(callbackHandlerFactory));
        callbackServer.addServlet(HeartbeatHandler.class, Optional.of(heartbeatServletFactory));

        callbackServer.start(LOCAL_PORT, HOST);
    }

    @AfterClass
    public static void tearDown() {
        TermdServer.stopServer();
        callbackServer.stop();
    }

    @Test
    public void shouldExecuteRemoteCommand()
            throws IOException, BuildAgentClientException, InterruptedException, ExecutionException, TimeoutException,
            URISyntaxException {
        CompletableFuture<String> callbackFuture = new CompletableFuture<>();
        Consumer<String> onResult = (s) -> callbackFuture.complete(s);
        responseConsumers.add(onResult);

        URI callbackUrl = new URI("http://" + HOST + ":" + LOCAL_PORT + "/" + CallbackHandler.class.getSimpleName());
        HeartbeatConfig heartbeatConfig = new HeartbeatConfig(
                new Request(
                        Request.Method.GET,
                        new URI("http://" + HOST + ":" + LOCAL_PORT + "/" + HeartbeatHandler.class.getSimpleName())),
                50L,
                TimeUnit.MILLISECONDS);
        HttpClientConfiguration clientConfiguration = HttpClientConfiguration.newBuilder()
                .callback(new Request(Request.Method.PUT, callbackUrl, Collections.emptyList(), null))
                .termBaseUrl(terminalBaseUrl)
                .heartbeatConfig(Optional.of(heartbeatConfig))
                .build();
        BuildAgentClient client = new BuildAgentHttpClient(clientConfiguration);

        client.execute(TEST_COMMAND_BASE + "10 100");

        Assert.assertNotNull(client.getSessionId());

        String callback = callbackFuture.get(3, TimeUnit.SECONDS);
        responseConsumers.remove(onResult);

        TaskStatusUpdateEvent callbackRequest = objectMapper.readValue(callback, TaskStatusUpdateEvent.class);
        Assert.assertEquals(Status.COMPLETED, callbackRequest.getNewStatus());

        Assert.assertTrue("Did not receive all heartbeats.", heartbeatCounter.get() > 20);
    }

    @Test
    public void shouldCancelRemoteCommand()
            throws IOException, BuildAgentClientException, InterruptedException, ExecutionException, TimeoutException,
            ServletException {
        CompletableFuture<String> callbackFuture = new CompletableFuture<>();
        Consumer<String> onResult = (s) -> callbackFuture.complete(s);
        responseConsumers.add(onResult);

        URL callbackUrl = new URL("http://" + HOST + ":" + LOCAL_PORT + "/" + CallbackHandler.class.getSimpleName());
        BuildAgentClient client = new BuildAgentHttpClient(terminalBaseUrl, callbackUrl, "PUT");
        client.execute(TEST_COMMAND_BASE + "4 250");

        Assert.assertNotNull(client.getSessionId());

        Thread.sleep(400);
        client.cancel();

        String callback = callbackFuture.get(3, TimeUnit.SECONDS);
        responseConsumers.remove(onResult);
        TaskStatusUpdateEvent callbackRequest = objectMapper.readValue(callback, TaskStatusUpdateEvent.class);
        Assert.assertEquals(Status.INTERRUPTED, callbackRequest.getNewStatus());

    }
}
