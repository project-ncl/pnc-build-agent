package org.jboss.pnc.buildagent.server.logging.performance;

import org.jboss.pnc.buildagent.server.IoQueueLogger;
import org.jboss.pnc.buildagent.server.QueueAdapter;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Properties;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class QueueLoggerTest {
    private static final Logger log = LoggerFactory.getLogger(QueueLoggerTest.class);

    public static final byte[] message = "01234567890123456789012345678901234567890123456789".getBytes(StandardCharsets.UTF_8);

    @Test @Ignore
    public void kafkaLoggerStressTest() throws InstantiationException, InterruptedException, IOException {
        QueueAdapter queueAdapter = new NoOpQueueAdapter();
        Properties properties = new Properties();
//        properties.load(new FileReader("kafka.properties"));
//        QueueAdapter queueAdapter = new KafkaQueueAdapter(properties, "test-topic");
        IoQueueLogger queueLogger = new IoQueueLogger(queueAdapter, true, 100, Collections.singletonMap("test", "true"));

        log.info("Writing first log line to warm up ...");
        queueLogger.writeOutput(message);

        long started = System.currentTimeMillis();
        log.info("Writing more logs ...");
        long written = 0;
        for (int i = 0; i < 100000; i++) {
            queueLogger.writeOutput(message);
            written+=message.length;
        }
        long took = System.currentTimeMillis() - started;
        log.info("Written {} byte in {} millis.", written, took);

        queueAdapter.close();

        long speed = written / took * 1000 / 1024;
        log.info("Throughput: {} kB/s.", speed);
    }
}
