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
import org.jboss.pnc.buildagent.common.BuildAgentException;
import org.jboss.pnc.buildagent.common.RandomUtils;
import org.jboss.pnc.buildagent.server.logging.Mdc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.jboss.pnc.buildagent.common.http.HttpClient.DEFAULT_HTTP_READ;
import static org.jboss.pnc.buildagent.common.http.HttpClient.DEFAULT_HTTP_WRITE;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class Main {

    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    private static final String DEFAULT_HOST = "localhost";
    private static final String DEFAULT_PORT = "8080";

    public static void main(String[] args) throws ParseException, BuildAgentException, InterruptedException, IOException {
        logger.info("Starting Build Agent.");
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
        options.addOption(null, "callbackMaxRetries",true, "How many times to retry failed completion callback.");
        options.addOption(null, "callbackWaitBeforeRetry",true, "How long to wait before completion callback retry (calculated as: attempt x duration-in-millis).");
        options.addOption(null, "bifrostURL",true, "Bifrost URL for final log upload.");
        options.addOption(null, "bifrostMaxRetries",true, "How many times to retry failed final log upload.");
        options.addOption(null, "bifrostWaitBeforeRetry",true, "How long to wait before final log upload retry (calculated as: attempt x duration-in-seconds).");
        options.addOption(null, "authHeaderConfig",true, "Path to authHeader config file. Must be set to enable endpoint protection.");
        options.addOption(null, "keycloakClientConfig", true, "Path to Keycloak client config file. Must be set to enable callback authentication");
        options.addOption(null, "httpReadTimeout", true, "Http client timeout for read operations. The value is number in milliseconds (default is " + DEFAULT_HTTP_READ + "ms).");
        options.addOption(null, "httpWriteTimeout", true, "Http client timeout for write operations. The value is number in milliseconds (default is " + DEFAULT_HTTP_WRITE + "ms).");
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

        Optional<Map<String, String>> mdcParamMap;
        if (logMDC != null && !logMDC.isEmpty()) {
             mdcParamMap = Mdc.parseMdc(logMDC);
        } else {
            mdcParamMap = Optional.empty();
        }

        Map<String, String> mdcMap;
        if (mdcParamMap.isPresent()) {
            mdcMap = mdcParamMap.get();
        } else {
            mdcMap = new HashMap<>();
            mdcMap.put("processContext", RandomUtils.randString(12));
        }

        if (cmd.hasOption("h")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("...", options);
            return;
        }

        String host = getOption(cmd, "b", DEFAULT_HOST);
        int port = Integer.parseInt(getOption(cmd, "p", DEFAULT_PORT));

        String bifrostURL = getOption(cmd, "bifrostURL", null);
        BifrostUploaderOptions bifrostUploaderOptions = null;
        if(bifrostURL != null){
            int bifrostMaxRetries = Integer.parseInt(getOption(cmd, "bifrostMaxRetries", "6"));
            int bifrostWaitBeforeRetry = Integer.parseInt(getOption(cmd, "bifrostWaitBeforeRetry", "10"));
            bifrostUploaderOptions = new BifrostUploaderOptions(bifrostURL, bifrostMaxRetries, bifrostWaitBeforeRetry, mdcMap);
        }

        String logPathString = getOption(cmd, "l", null);
        Optional<Path> logPath;
        if (logPathString != null) {
            logPath = Optional.of(Paths.get(logPathString));
        } else if (bifrostUploaderOptions != null) {
            logPath = Optional.of(Files.createTempDirectory("outputlogs"));
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
        List<IoLoggerName> primaryLogersList = Arrays.stream(primaryLoggersStrArr)
                .map(IoLoggerName::valueOf)
                .collect(Collectors.toList());
        IoLoggerName[] primaryLoggers = primaryLogersList.toArray(new IoLoggerName[primaryLogersList.size()]);

        String bindPath = getOption(cmd, "c", "");
        boolean socketInvokerEnabled = Boolean.parseBoolean(getOption(cmd, "enableSocketInvoker", "true"));
        boolean httpInvokerEnabled = Boolean.parseBoolean(getOption(cmd, "enableHttpInvoker", "false"));
        int callbackMaxRetries = Integer.parseInt(getOption(cmd, "callbackMaxRetries", "10"));
        long callbackWaitBeforeRetry = Long.parseLong(getOption(cmd, "callbackWaitBeforeRetry", "500"));
        String authHeaderConfigFile = getOption(cmd, "authHeaderConfig", "");
        String keycloakClientConfigFile = getOption(cmd, "keycloakClientConfig", "");

        String httpReadTimeoutString = getOption(cmd, "httpReadTimeout", null);
        int httpReadTimeout;
        if (httpReadTimeoutString != null) {
            httpReadTimeout = Integer.parseInt(httpReadTimeoutString);
        } else {
            String env = System.getenv("BUILD_AGENT_HTTP_READ_TIMEOUT");
            if (env != null) {
                httpReadTimeout = Integer.parseInt(env);
            } else {
                httpReadTimeout = DEFAULT_HTTP_READ;
            }
        }

        String httpWriteTimeoutString = getOption(cmd, "httpWriteTimeout", null);
        int httpWriteTimeout;
        if (httpWriteTimeoutString != null) {
            httpWriteTimeout = Integer.parseInt(httpWriteTimeoutString);
        } else {
            String env = System.getenv("BUILD_AGENT_HTTP_WRITE_TIMEOUT");
            if (env != null) {
                httpWriteTimeout = Integer.parseInt(env);
            } else {
                httpWriteTimeout = DEFAULT_HTTP_WRITE;
            }
        }

        org.jboss.pnc.buildagent.server.Options buildAgentOptions = new org.jboss.pnc.buildagent.server.Options(
                host,
                port,
                bindPath,
                socketInvokerEnabled,
                httpInvokerEnabled,
                callbackMaxRetries,
                callbackWaitBeforeRetry,
                bifrostUploaderOptions,
                authHeaderConfigFile,
                keycloakClientConfigFile,
                httpReadTimeout,
                httpWriteTimeout);

        new BuildAgentServer(
                logPath,
                kafkaPropertiesPath,
                primaryLoggers,
                buildAgentOptions,
                mdcMap);
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
