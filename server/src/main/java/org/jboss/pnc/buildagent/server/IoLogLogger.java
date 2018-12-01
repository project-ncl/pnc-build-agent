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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public class IoLogLogger implements ReadOnlyChannel {

    static final Logger processLog = LoggerFactory.getLogger("org.jboss.pnc._userlog_.build-log");
    private static final Logger log = LoggerFactory.getLogger(IoLogLogger.class);
    private Charset charset = Charset.defaultCharset();
    private Consumer<byte[]> outputLogger;

    public IoLogLogger(Map<String, String> logMDC) {
        outputLogger = (bytes) -> {
            MDC.setContextMap(logMDC);
            processLog.info(new String(bytes, charset));
        };
    }

    @Override
    public void flush() throws IOException {
        throw new IOException(new UnsupportedOperationException("Not implemented! IoLogLogger can not be used as primary."));
    }

    @Override
    public void close() {
        log.info("Closing IoLogLogger.");
    }

    @Override
    public void writeOutput(byte[] buffer) {
        outputLogger.accept(buffer);
    }

    @Override
    public boolean isPrimary() {
        return false;
    }
}
