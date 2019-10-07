package org.jboss.pnc.buildagent.server;

import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Properties;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class KafkaQueueAdapter implements QueueAdapter {

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
        ProducerRecord<String, String> producerRecord = new ProducerRecord<>(queueTopic, message);
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
