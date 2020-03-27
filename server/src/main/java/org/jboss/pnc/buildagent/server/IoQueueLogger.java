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

import org.jboss.pnc.buildagent.api.logging.LogFormatter;
import org.jboss.pnc.buildagent.common.LineConsumer;
import org.jboss.pnc.buildagent.server.logging.formatters.jboss.JBossFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;
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
public class IoQueueLogger implements ReadOnlyChannel {

    private static final Logger log = LoggerFactory.getLogger(IoQueueLogger.class);
    private Charset charset = Charset.defaultCharset();

    private Consumer<byte[]> outputLogger;

    private final boolean primary;

    private final AtomicReference<Exception> deliveryException = new AtomicReference<>();

    private long flushTimeoutMillis;

    private final QueueAdapter queueAdapter;

    private final LineConsumer lineConsumer;

    public IoQueueLogger(QueueAdapter queueAdapter, boolean primary, long flushTimeoutMillis, Map<String, String> logMDC)
            throws InstantiationException, UnsupportedEncodingException {
        this.primary = primary;
        this.flushTimeoutMillis = flushTimeoutMillis;
        this.queueAdapter = queueAdapter;

        ServiceLoader<LogFormatter> loader = ServiceLoader.load(LogFormatter.class);
        Iterator<LogFormatter> iterator = loader.iterator();
        LogFormatter logFormatter = getLogFormatter(iterator);

        Consumer<Exception> exceptionHandler = (e) -> {
            log.error("Error writing log.", e);
            deliveryException.compareAndSet(null, e);
        };

        Consumer<String> onLine = (line)-> {
            String messageJson = logFormatter.format(line);
            queueAdapter.send(messageJson, exceptionHandler);
        };
        lineConsumer = new LineConsumer(onLine, StandardCharsets.UTF_8);

        outputLogger = (bytes) -> {
            MDC.setContextMap(logMDC);
            lineConsumer.append(bytes);
        };
    }

    private LogFormatter getLogFormatter(Iterator<LogFormatter> iterator) throws InstantiationException {
        LogFormatter logFormatter = null;
        if (iterator.hasNext()) {
            logFormatter = iterator.next();
        }
        if (iterator.hasNext()) {
            log.warn("Multiple formatter found, using: " + logFormatter.getClass());
        }
        if (logFormatter == null) {
            logFormatter = new JBossFormatter();
        }
        return logFormatter;
    }

    @Override
    public void flush() throws IOException {
        lineConsumer.flush();
        Exception e = deliveryException.get();
        if (e != null) {
            throw new IOException("Some messages were not written.", e);
        }
        ExecutorService executorService = Executors.newFixedThreadPool(1);

        Future<?> future = executorService.submit(() -> queueAdapter.flush());

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

    public void close(Duration duration) throws IOException {
        queueAdapter.close(duration);
    }

    public void close() throws IOException {
        log.info("Closing IoQueueLogger.");
        queueAdapter.close();
    }


}
