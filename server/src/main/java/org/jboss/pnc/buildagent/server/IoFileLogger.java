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

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.jboss.pnc.buildagent.common.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public class IoFileLogger implements ReadOnlyChannel {

    Logger log = LoggerFactory.getLogger(IoFileLogger.class);
    private Charset charset = Charset.defaultCharset();
    private Consumer<String> inputLogger;
    private Consumer<byte[]> outputLogger;

    FileOutputStream stream;

    private final boolean primary;

    private final Path logPath;

    public IoFileLogger(Path logFolder, boolean primary) {
        this.primary = primary;
        logPath = logFolder.resolve("console.log");
        try {

            log.info("Opening log file {}.", logPath);
            stream = new FileOutputStream(logPath.toFile(), true);

            inputLogger = (line) -> {
                try {
                    String command = "% " + line + "\r\n";
                    stream.write(command.getBytes(charset));
                } catch (IOException e) {
                    log.error("Cannot write command line to log file.", e);
                }
            };

            outputLogger = (bytes) -> {
                try {
                    stream.write(bytes);
                } catch (IOException e) {
                    String bytesAsInts = java.util.Arrays.stream(Arrays.bytesToInts(bytes))
                            .mapToObj(i -> Integer.toString(i))
                            .collect(Collectors.joining(", "));
                    log.error(
                            "Cannot write bytes [" + bytesAsInts + "] to file. IsPrimaryLogger: " + isPrimary() + "",
                            e);
                }
            };

        } catch (IOException e) {
            log.error("Cannot open fileChannel: ", e);
        }
    }

    @Override
    public void flush() throws IOException {
        stream.flush();
    }

    @Override
    public void close() throws IOException {
        stream.close();
    }

    @Override
    public void writeOutput(byte[] buffer) {
        outputLogger.accept(buffer);
    }

    @Override
    public boolean isPrimary() {
        return primary;
    }

    public Path getLogPath() {
        return logPath;
    }
}
