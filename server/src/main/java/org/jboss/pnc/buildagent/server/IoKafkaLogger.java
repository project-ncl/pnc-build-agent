/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.pnc.buildagent.server;

import ch.qos.logback.core.status.Status;
import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.jboss.pnc.buildagent.server.formatter.LogbackFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public class IoKafkaLogger implements ReadOnlyChannel {

    static final Logger processLog = LoggerFactory.getLogger("org.jboss.pnc._userlog_.build-log");

    private final String queueTopic;
    private final KafkaProducer kafkaProducer;

    List<Status> loggerErrors = new ArrayList<>();
    private static final Logger log = LoggerFactory.getLogger(IoKafkaLogger.class);
    private Charset charset = Charset.defaultCharset();

    private Consumer<byte[]> outputLogger;

    private final boolean primary;

    private final AtomicReference<Exception> deliveryException = new AtomicReference<>();

    private long flushTimeoutMillis;

    public IoKafkaLogger(Properties properties, String queueTopic, boolean primary, long flushTimeoutMillis, Map<String, String> logMDC) {
        this.queueTopic = queueTopic;
        this.primary = primary;
        this.flushTimeoutMillis = flushTimeoutMillis;
        kafkaProducer = new KafkaProducer<>(properties);
        LogbackFormatter logbackFormatter = new LogbackFormatter();

        Consumer<Exception> exceptionHandler = (e) -> {
            log.error("Error writing log.", e);
            deliveryException.compareAndSet(null, e);
        };
        outputLogger = (bytes) -> {
            MDC.setContextMap(logMDC);

            String messageJson = logbackFormatter.format(new String(bytes, charset));
            send(messageJson, exceptionHandler);
        };
    }

    @Override
    public void flush() throws IOException {
        Exception e = deliveryException.get();
        if (e != null) {
            throw new IOException("Some messages were not written.", e);
        }
        ExecutorService executorService = Executors.newFixedThreadPool(1);

        Future<?> future = executorService.submit(() -> kafkaProducer.flush());

        try {
            future.get(flushTimeoutMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | TimeoutException | ExecutionException futureException) {
            future.cancel(true);
            throw new IOException("Unable to flush logs.", futureException);
        }
    }

    @Override
    public void writeOutput(byte[] buffer) {
        outputLogger.accept(buffer);
    }

    @Override
    public boolean isPrimary() {
        return primary;
    }

    private void send(String message, Consumer<Exception> exceptionHandler) {
        ProducerRecord<String, String> producerRecord = new ProducerRecord<>(queueTopic, message);
            Callback callback = (metadata, exception) -> {
            if (exception != null) {
                exceptionHandler.accept(exception);
            } else {
                log.trace("Message sent to Kafka. Partition:{}, timestamp {}.", metadata.partition(), metadata.timestamp());
            }
        };
        kafkaProducer.send(producerRecord, callback);
    }

    /**
     * Blocking send
     */
    private void send(String message, long timeoutMillis) throws TimeoutException, ExecutionException, InterruptedException {
        ProducerRecord<String, String> producerRecord = new ProducerRecord<>(queueTopic, message);
        Future<RecordMetadata> future = kafkaProducer.send(producerRecord);
        future.get(timeoutMillis, TimeUnit.MILLISECONDS);
    }

    public void close(long timeout, TimeUnit timeUnit) throws IOException {
        kafkaProducer.close(timeout, timeUnit);
    }

    public void close() throws IOException {
        log.info("Closing IoKafkaLogger.");
        kafkaProducer.close();
    }


}
