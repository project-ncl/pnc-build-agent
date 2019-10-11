package org.jboss.pnc.buildagent.server;

import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.jboss.pnc.buildagent.client.BuildAgentSocketClient;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
public class ConcurrentStdInOut {
    private static final String HOST = "localhost";
    private static final int PORT = TermdServer.getNextPort();
    private static Logger log = LoggerFactory.getLogger(ConcurrentStdInOut.class);

    @BeforeClass
    public static void setUP() throws Exception {
        System.setProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager");
        TermdServer.startServer(HOST, PORT, "", true, true);
    }

    @AfterClass
    public static void tearDown() {
        TermdServer.stopServer();
    }

    @Test
    public void simpleProcessOutput() throws IOException, InterruptedException {
        boolean redirectErrorStream = true;
        String TEST_COMMAND = "./server/src/test/resources/testscript.sh";
        ProcessBuilder builder = new ProcessBuilder(TEST_COMMAND);
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
    public void shouldNotMixStdInAndStdoutLines() throws Exception {
        String longMessage = createLongMessage();
//        String TEST_COMMAND = "java -cp ./target/test-classes/:./server/target/test-classes/ org.jboss.pnc.buildagent.server.MockProcess 1 0 " + longMessage + "";
//        String TEST_COMMAND = "pwd";
        String TEST_COMMAND = "./server/src/test/resources/testscript.sh";

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
            log.debug("Response line: {}", response);
        }

        int commandOutputIndex = responses.indexOf("123456789123456789");
        int commandInputIndex = responses.indexOf("+ echo 123456789123456789");

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
