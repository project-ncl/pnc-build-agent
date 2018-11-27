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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.jboss.pnc.buildagent.common.RandomUtils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class Main {
    private static final String DEFAULT_HOST = "localhost";
    private static final String DEFAULT_PORT = "8080";

    public static void main(String[] args) throws ParseException, BuildAgentException, InterruptedException {
        Options options = new Options();
        options.addOption("b", true, "Address to bind. When not specified " + DEFAULT_HOST + " is used as default.");
        options.addOption("p", true, "Port to bind. When not specified " + DEFAULT_PORT + " is used as default.");
        options.addOption("l", true, "Path to folder where process logs are stored. If undefined logs are not written.");
        options.addOption("c", true, "Bind path. A URL mapping path that is used as a prefix to the path. eg. domain.com/<bind-path>/socket");
        options.addOption("kp",true, "Path to kafka properties file.");
        options.addOption("pl",true, "List of primary loggers. eg. -pl FILE,KAFKA");
        options.addOption(null, "logMDC",true, "Logging Mapped Diagnostic Context.");
        options.addOption(null, "enableSocketInvoker",true, "Enable Websocket invoker.");
        options.addOption(null, "enableHttpInvoker",true, "Enable http with callback invoker.");
        options.addOption("h", false, "Print this help message.");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse( options, args);

        String logMDC = getOption(cmd, "logMDC", null);
        if (logMDC == null) {
            logMDC = System.getProperty("logMDC");
        }
        if (logMDC == null) {
            logMDC = System.getenv("logMDC");
        }
        if (logMDC == null) {
            logMDC = RandomUtils.randString(12);
        }

        if (cmd.hasOption("h")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("...", options);
            return;
        }

        String host = getOption(cmd, "b", DEFAULT_HOST);
        int port = Integer.parseInt(getOption(cmd, "p", DEFAULT_PORT));

        String logPathString = getOption(cmd, "l", null);
        Optional<Path> logPath;
        if (logPathString != null) {
            logPath = Optional.of(Paths.get(logPathString));
        } else {
            logPath = Optional.empty();
        }

        String kafkaPropertiesString = getOption(cmd, "kp", null);
        Optional<Path> kafkaPropertiesPath;
        if (kafkaPropertiesString != null) {
            kafkaPropertiesPath = Optional.of(Paths.get(kafkaPropertiesString));
        } else {
            kafkaPropertiesPath = Optional.empty();
        }

        String primaryLoggersString = getOption(cmd, "pl", "FILE");
        String[] primaryLoggersStrArr = primaryLoggersString.split(",");
        List<IoLoggerName> primaryLogersList = Arrays.asList(primaryLoggersStrArr).stream()
                .map(l -> IoLoggerName.valueOf(l))
                .collect(Collectors.toList());
        IoLoggerName[] primaryLoggers = primaryLogersList.toArray(new IoLoggerName[primaryLogersList.size()]);

        String bindPath = getOption(cmd, "c", "");
        boolean socketInvokerEnabled = Boolean.parseBoolean(getOption(cmd, "enableSocketInvoker", "true"));
        boolean httpInvokerEnabled = Boolean.parseBoolean(getOption(cmd, "enableHttpInvoker", "false"));

        org.jboss.pnc.buildagent.server.Options buildAgentOptions = new org.jboss.pnc.buildagent.server.Options(
                host,
                port,
                bindPath,
                socketInvokerEnabled,
                httpInvokerEnabled
        );

        new BuildAgentServer(
                logPath,
                kafkaPropertiesPath,
                primaryLoggers,
                buildAgentOptions,
                logMDC);
    }

    private static String getOption(CommandLine cmd, String opt, String defaultValue) {
        if (cmd.hasOption(opt)) {
            return cmd.getOptionValue(opt);
        } else {
            return defaultValue;
        }
    }
    private static Option longOption(String longOpt, String description) {
        return Option.builder().longOpt(longOpt)
                .desc(description)
                .build();
    }


}
