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

import org.jboss.pnc.buildagent.common.BuildAgentException;
import org.jboss.pnc.buildagent.common.RandomUtils;
import org.jboss.pnc.buildagent.common.http.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class TermdServer {

    public static final String HOST = "localhost";

    private static final AtomicInteger port_pool = new AtomicInteger(8090);

    private static BuildAgentServer buildAgentServer;

    private static final Logger log = LoggerFactory.getLogger(TermdServer.class);

    public static int getNextPort() {
        return port_pool.getAndIncrement();
    }

    @Deprecated
    public static void startServer(String host, int port, String bindPath) throws InterruptedException {
        startServer(host, port, bindPath, true, true);
    }

    /**
     * Try to start the build agent and block until it is up and running.
     */
    public static void startServer(String host, int port, String bindPath, boolean enableSocketInvoker, boolean writeLogFile) throws InterruptedException {
        Optional<Path> logFolder;
        IoLoggerName[] primaryLoggers;
        if (writeLogFile) {
            logFolder = Optional.of(Paths.get("").toAbsolutePath());
            primaryLoggers = new IoLoggerName[] { IoLoggerName.FILE};
        } else {
            logFolder = Optional.empty();
            primaryLoggers = new IoLoggerName[0];
        }
        try {
            Options options = new Options(
                    host,
                    port,
                    bindPath,
                    enableSocketInvoker,
                    !enableSocketInvoker,
                    10,
                    500,
                    null,
                    "",
                    "",
                    "",
                    HttpClient.DEFAULT_HTTP_READ,
                    HttpClient.DEFAULT_HTTP_WRITE);
            Map<String, String> mdcMap = new HashMap<>();
            mdcMap.put("ctx", RandomUtils.randString(6));

            buildAgentServer = new BuildAgentServer(
                    logFolder,
                    Optional.empty(),
                    primaryLoggers,
                    options,
                    mdcMap);
            log.info("Server started.");
        } catch (BuildAgentException e) {
            throw new RuntimeException("Cannot start terminal server.", e);
        }
    }

    public static void stopServer() {
        log.info("Stopping server...");
        buildAgentServer.stop();
        log.info("Server stopped.");
    }

}
