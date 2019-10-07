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

import org.jboss.pnc.buildagent.server.termserver.Term;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
  */
public class BuildAgentServer {

    private final Logger log = LoggerFactory.getLogger(BuildAgentServer.class);
    private BootstrapUndertow undertowBootstrap;
    private final ScheduledExecutorService executor = new ScheduledThreadPoolExecutor(1);
    Set<ReadOnlyChannel> sinkChannels = new HashSet<>();

    private final Options options;

    /**
     * @throws BuildAgentException is thrown if server is unable to start.
     */
    public BuildAgentServer(
            Optional<Path> logPath,
            Optional<Path> kafkaConfig,
            IoLoggerName[] primaryLoggersArr,
            Options options,
            Map<String, String> logMDC) throws BuildAgentException {
        this.options = options;
        init(logPath, kafkaConfig, primaryLoggersArr, logMDC);
    }
    /**
     * Blocks the operation until the server is started.
     *
     * @throws BuildAgentException is thrown if server is unable to start.
     */
    private void init(
            Optional<Path> logPath,
            Optional<Path> kafkaConfig,
            IoLoggerName[] primaryLoggersArr,
            Map<String, String> logMDC) throws BuildAgentException {

        List<IoLoggerName> primaryLoggers = Arrays.asList(primaryLoggersArr);

        if (IoLogLogger.processLog.isInfoEnabled()) {
            log.info("Initializing Logger sink.");
            sinkChannels.add(new IoLogLogger(logMDC));
        }

        if (logPath.isPresent()) {
            log.info("Initializing File sink.");
            sinkChannels.add(new IoFileLogger(logPath.get(), isPrimary(primaryLoggers, IoLoggerName.FILE)));
        }

        if (kafkaConfig.isPresent()) {
            log.info("Initializing Kafka sink.");
            Properties properties = new Properties();
            try {
                properties.load(new FileReader(kafkaConfig.get().toFile()));
            } catch (IOException e) {
                throw new BuildAgentException("Cannot read kafka properties.", e);
            }
            String queueTopic = properties.getProperty("pnc.queue_topic", "pnc-logs");
            long flushTimeoutMillis = Long.parseLong(properties.getProperty("pnc.flush_timeout_millis", "10000"));

            try {
                KafkaQueueAdapter kafkaQueueAdapter = new KafkaQueueAdapter(properties, queueTopic);
                sinkChannels.add(new IoQueueLogger(kafkaQueueAdapter, isPrimary(primaryLoggers, IoLoggerName.KAFKA), flushTimeoutMillis, logMDC));
            } catch (InstantiationException e) {
                throw new BuildAgentException("Cannot initialize Kafka logger.", e);
            }
        }

        try {
            undertowBootstrap = new BootstrapUndertow(
                    executor,
                    sinkChannels,
                    options
            );
            log.info("Server started on " + options.getHost() + ":" + options.getPort());
        } catch (BuildAgentException e) {
            throw e;
        }
    }

    private boolean isPrimary(List<IoLoggerName> primaryLoggers, IoLoggerName name) {
        if (primaryLoggers.contains(name)) {
            log.info("Logger {} is primary.", name);
            return true;
        } else {
            return false;
        }
    }

    public int getPort() {
        return options.getPort();
    }

    public String getHost() {
        return options.getHost();
    }

    public void stop() {
        log.info("Stopping BuildAgentServer.");
        for (ReadOnlyChannel sinkChannel : sinkChannels) {
            try {
                sinkChannel.close();
            } catch (IOException e) {
                log.error("Cannot close ioLogger.", e);
            }
        }
        for (Term term : undertowBootstrap.getTerms().values()) {
            term.close();
        }

        undertowBootstrap.stop();
    }
}
