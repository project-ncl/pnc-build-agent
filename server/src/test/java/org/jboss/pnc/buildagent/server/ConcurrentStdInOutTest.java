package org.jboss.pnc.buildagent.server;

import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.jboss.pnc.buildagent.client.BuildAgentSocketClient;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class ConcurrentStdInOutTest {
    private static final String HOST = "localhost";
    private static final int PORT = TermdServer.getNextPort();
    private static final Logger log = LoggerFactory.getLogger(ConcurrentStdInOutTest.class);

    @BeforeClass
    public static void setUP() throws Exception {
        TermdServer.startServer(HOST, PORT, "", true, true);
    }

    @AfterClass
    public static void tearDown() {
        TermdServer.stopServer();
    }

    @Test
    @Ignore
    public void simpleProcessOutput() throws IOException, InterruptedException, URISyntaxException {
        boolean redirectErrorStream = true;
        URL scriptResource = ConcurrentStdInOutTest.class.getResource("/testscript.sh");
        ProcessBuilder builder = new ProcessBuilder(Paths.get(scriptResource.toURI()).toAbsolutePath().toString());
        builder.redirectErrorStream(redirectErrorStream);
        Process process = builder.start();
        Pipe stdout = new Pipe(process.getInputStream());
        Pipe stderr = null;
        if (!redirectErrorStream) {
            stderr = new Pipe(process.getErrorStream());
            stderr.start();
        }
        stdout.start();
        stdout.join();
        if (stderr != null) {
            stderr.join();
        }
    }

    class Pipe extends Thread {

        private InputStream stream;

        public Pipe(InputStream stream) {
            this.stream = stream;
        }

        @Override
        public void run() {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
                for (String line; (line = reader.readLine()) != null; ) {
                    System.out.println(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    @Test
    public void shouldNotMixStdInAndStdoutLines() throws Throwable {
        String longMessage = createLongMessage();
//        String TEST_COMMAND = "java -cp ./target/test-classes/:./server/target/test-classes/ org.jboss.pnc.buildagent.server.MockProcess 1 0 " + longMessage + "";
//        String TEST_COMMAND = "pwd";
        URL scriptResource = ConcurrentStdInOutTest.class.getResource("/testscript.sh");
        String TEST_COMMAND = Paths.get(scriptResource.toURI()).toAbsolutePath().toString();

        String terminalUrl = "http://" + HOST + ":" + PORT;

        String context = this.getClass().getName() + ".concurrentStdInOut";

        BlockingQueue<String> queue = new ArrayBlockingQueue(1000);
        List<String> responses = new ArrayList<>();

        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            queue.offer(statusUpdateEvent.getNewStatus().toString());
        };
        Consumer<String> responseConsumer = s -> {
            responses.add(s);
        };
        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalUrl, Optional.of(responseConsumer), onStatusUpdate, context);
        buildAgentClient.executeCommand(TEST_COMMAND);

        String received = queue.poll(5, TimeUnit.SECONDS);
        log.info("Received status: {}", received);

        received = queue.poll(5, TimeUnit.SECONDS);
        log.info("Received status: {}", received);

        for (String response : responses) {
            log.info("Response line: {}", response);
        }

        int commandInputIndex = responses.indexOf("+ echo abc");
        int commandOutputIndex = responses.indexOf("abc");

        Assert.assertTrue("Command input have to be printed before its output.", commandOutputIndex > commandInputIndex);
    }

    private String createLongMessage() {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            stringBuilder.append("Longinputmessage.");
        }
        return stringBuilder.toString();
    }
}
