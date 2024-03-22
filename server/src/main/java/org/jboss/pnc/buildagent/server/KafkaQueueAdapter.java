package org.jboss.pnc.buildagent.server;

import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.jboss.pnc.api.constants.MDCKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.Properties;
import java.util.Random;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class KafkaQueueAdapter implements QueueAdapter {

    /**
     * This is the default key we'll use for sending messages to Kafka if the processKey of the message is not specified
     * and will stay consistent while the app is running!
     *
     * Why is it the same for the duration the app is running? So that all the logs go to the same partition in the
     * Kafka topic, to preserve order
     *
     * Why is it randomly generated at the beginning? So that when we select a random partition at the beginning, rather
     * than sending messages to the same partition all the time and potentially creating a hotspot when all the
     * build-agent instances run at the same time.
     */
    private static final String DEFAULT_KEY = String.valueOf(new Random().nextInt(8192));
    private static final Logger log = LoggerFactory.getLogger(KafkaQueueAdapter.class);

    private final KafkaProducer kafkaProducer;
    private final String queueTopic;

    public KafkaQueueAdapter(Properties kafkaProperties, String queueTopic) {
        this.queueTopic = queueTopic;
        kafkaProducer = new KafkaProducer<>(kafkaProperties);
    }

    @Override
    public void flush() {
        kafkaProducer.flush();
    }

    @Override
    public void send(String message, Consumer<Exception> exceptionHandler) {

        String key = MDC.get(MDCKeys.PROCESS_CONTEXT_KEY);

        if (key == null || key.isEmpty()) {
            // fallback key to use in case processContext is not specified in the MDC
            key = DEFAULT_KEY;
        }

        ProducerRecord<String, String> producerRecord = new ProducerRecord<>(queueTopic, key, message);
        Callback callback = (metadata, exception) -> {
            if (exception != null) {
                exceptionHandler.accept(exception);
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("Message sent to Kafka. Partition:{}, timestamp {}.", metadata.partition(), metadata.timestamp());
                }
            }
        };
        kafkaProducer.send(producerRecord, callback);
    }

    @Override
    public void close(Duration duration) {
        kafkaProducer.close(duration);
    }

    @Override
    public void close() {
        kafkaProducer.close();
    }
}
