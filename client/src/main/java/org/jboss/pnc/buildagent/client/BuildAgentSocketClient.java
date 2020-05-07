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

package org.jboss.pnc.buildagent.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.pnc.buildagent.api.ResponseMode;
import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.websocket.ClientEndpointConfig;
import javax.websocket.CloseReason;
import javax.websocket.ContainerProvider;
import javax.websocket.Session;
import javax.websocket.WebSocketContainer;
import java.io.IOException;
import java.net.URI;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * @see "https://github.com/undertow-io/undertow/blob/5bdddf327209a4abf18792e78148863686c26e9b/websockets-jsr/src/test/java/io/undertow/websockets/jsr/test/BinaryEndpointTest.java"
 *
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class BuildAgentSocketClient extends BuildAgentClientBase implements BuildAgentClient {

    private static final Logger log = LoggerFactory.getLogger(BuildAgentSocketClient.class);

    private static final WebSocketContainer webSocketContainer = ContainerProvider.getWebSocketContainer();

    private String commandContext;

    private final ResponseMode responseMode;
    private final boolean readOnly;

    private RemoteEndpoint statusUpdatesEndpoint;
    private RemoteEndpoint commandExecutingEndpoint;

    private AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * @see BuildAgentHttpClient(Optional<Consumer<String>>, Consumer<TaskStatusUpdateEvent>, SocketClientConfiguration )
     */
    public BuildAgentSocketClient(String termBaseUrl,
                            Optional<Consumer<String>> responseDataConsumer,
                            Consumer<TaskStatusUpdateEvent> onStatusUpdate,
                            String commandContext
                        ) throws TimeoutException, InterruptedException, BuildAgentClientException {
        this(termBaseUrl, responseDataConsumer, onStatusUpdate, commandContext, ResponseMode.BINARY, false);
    }

    /**
     * @see BuildAgentHttpClient(Optional<Consumer<String>>, Consumer<TaskStatusUpdateEvent>, SocketClientConfiguration )
     */
    @Deprecated
    public BuildAgentSocketClient(String termBaseUrl,
            Optional<Consumer<String>> responseDataConsumer,
            Consumer<TaskStatusUpdateEvent> onStatusUpdate,
            String commandContext,
            ResponseMode responseMode,
            boolean readOnly) throws TimeoutException, InterruptedException, BuildAgentClientException {
        super(termBaseUrl, 30000);
        this.commandContext = formatCommandContext(commandContext);
        this.responseMode = responseMode;
        this.readOnly = readOnly;

        Consumer<TaskStatusUpdateEvent> onStatusUpdateInternal = (event) -> {
            onStatusUpdate.accept(event);
        };

        statusUpdatesEndpoint = connectStatusListenerClient(termBaseUrl, onStatusUpdateInternal);
        commandExecutingEndpoint = connectCommandExecutingClient(termBaseUrl, responseDataConsumer);
    }

    public BuildAgentSocketClient(
            Optional<Consumer<String>> responseDataConsumer,
            Consumer<TaskStatusUpdateEvent> onStatusUpdate,
            SocketClientConfiguration configuration)
            throws TimeoutException, InterruptedException, BuildAgentClientException {
        super(configuration.getTermBaseUrl(), configuration.getLivenessResponseTimeout());
        this.commandContext = formatCommandContext(configuration.getCommandContext());
        this.responseMode = configuration.getResponseMode();
        this.readOnly = configuration.isReadOnly();

        Consumer<TaskStatusUpdateEvent> onStatusUpdateInternal = (event) -> {
            onStatusUpdate.accept(event);
        };

        String termBaseUrl = configuration.getTermBaseUrl();
        statusUpdatesEndpoint = connectStatusListenerClient(termBaseUrl, onStatusUpdateInternal);
        commandExecutingEndpoint = connectCommandExecutingClient(termBaseUrl, responseDataConsumer);
    }

    @Deprecated
    public void executeCommand(String command) throws BuildAgentClientException {
        execute(command);
    }

    public void execute(Object command) throws BuildAgentClientException {
        log.info("Executing remote command [{}]...", command);
        javax.websocket.RemoteEndpoint.Basic remoteEndpoint = commandExecutingEndpoint.getRemoteEndpoint();

        ByteBuffer byteBuffer = prepareRemoteCommand(command);

        try {
            log.debug("Sending remote command...");
            remoteEndpoint.sendBinary(byteBuffer);
            log.debug("Command sent.");
        } catch (IOException e) {
            log.error("Cannot execute remote command.", e);
        }
    }

    public void cancel() throws BuildAgentClientException {
        execute('C' - 64); //send ctrl+C
    }

    @Override
    public String getSessionId() {
        return commandContext;
    }

    private ByteBuffer prepareRemoteCommand(Object command) throws BuildAgentClientException {
        Map<String, Object> cmdJson = new HashMap<>();
        cmdJson.put("action", "read");

        ByteBuffer byteBuffer;
        if (command instanceof String) {
            cmdJson.put("data", command + "\n");
            ObjectMapper mapper = new ObjectMapper();
            try {
                byteBuffer = ByteBuffer.wrap(mapper.writeValueAsBytes(cmdJson));
            } catch (JsonProcessingException e) {
                throw new BuildAgentClientException("Cannot serialize string command.", e);
            }
        } else {
            try {
                byteBuffer = ByteBuffer.allocate(1).put(((Integer)command).byteValue());
            } catch (BufferOverflowException | ClassCastException e) {
                throw new BuildAgentClientException("Invalid signal.", e);
            }
            byteBuffer.flip();
        }
        return byteBuffer;
    }

    private RemoteEndpoint connectStatusListenerClient(String webSocketBaseUrl, Consumer<TaskStatusUpdateEvent> onStatusUpdate) {
        RemoteEndpoint client = initializeDefault("statusListener");
        Consumer<String> responseConsumer = (text) -> {
            log.trace("Decoding response: {}", text);

            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonObject = null;
            try {
                jsonObject = mapper.readTree(text);
            } catch (IOException e) {
                log.error( "Cannot read JSON string: " + text, e);
            }
            try {
                TaskStatusUpdateEvent taskStatusUpdateEvent = mapper.treeToValue(jsonObject.get("event"), TaskStatusUpdateEvent.class);
                onStatusUpdate.accept(taskStatusUpdateEvent);
            } catch (IOException e) {
                log.error("Cannot deserialize TaskStatusUpdateEvent.", e);
            }
        };
        client.onStringMessage(responseConsumer);

        try {
            String websocketUrl = stripEndingSlash(webSocketBaseUrl) + RemoteEndpoint.WEB_SOCKET_LISTENER_PATH + commandContext;
            ClientEndpointConfig clientEndpointConfig = ClientEndpointConfig.Builder.create().build();
            webSocketContainer.connectToServer(client, clientEndpointConfig, new URI(websocketUrl));
        } catch (Exception e) {
            throw new AssertionError("Failed to connect to remote client.", e);
        }
        return client;
    }

    private RemoteEndpoint connectCommandExecutingClient(String webSocketBaseUrl, Optional<Consumer<String>> responseDataConsumer) throws InterruptedException, TimeoutException {

        RemoteEndpoint client = initializeDefault("commandExecuting");

        if (ResponseMode.TEXT.equals(responseMode)) {
            registerTextResponseConsumer(responseDataConsumer, client);
        } else if (ResponseMode.BINARY.equals(responseMode)) {
            registerBinaryResponseConsumer(responseDataConsumer, client);
        } else {
            log.info("Connecting commandExecutingClient in silent mode.");
            //must be silent mode
        }

        String appendReadOnly = readOnly ? "/ro" : "";

        String webSocketPath;
        if (ResponseMode.TEXT.equals(responseMode)) {
            webSocketPath = stripEndingSlash(webSocketBaseUrl) + RemoteEndpoint.WEB_SOCKET_TERMINAL_TEXT_PATH;
        } else if (ResponseMode.BINARY.equals(responseMode)) {
            webSocketPath = stripEndingSlash(webSocketBaseUrl) + RemoteEndpoint.WEB_SOCKET_TERMINAL_PATH;
        } else {
            webSocketPath = stripEndingSlash(webSocketBaseUrl) + RemoteEndpoint.WEB_SOCKET_TERMINAL_SILENT_PATH;
        }

        try {
            String websocketUrl = webSocketPath + commandContext + appendReadOnly;
            ClientEndpointConfig clientEndpointConfig = ClientEndpointConfig.Builder.create().build();
            webSocketContainer.connectToServer(client, clientEndpointConfig, new URI(websocketUrl));
        } catch (Exception e) {
            throw new AssertionError("Failed to connect to remote client.", e);
        }
        return client;
    }

    private String formatCommandContext(String commandContext) {
        if (commandContext != null && !commandContext.equals("")) {
            commandContext = "/" + commandContext;
        }
        return commandContext;
    }

    private String stripEndingSlash(String path) {
        return path.replaceAll("/$", "");
    }

    private void registerBinaryResponseConsumer(Optional<Consumer<String>> responseDataConsumer, RemoteEndpoint client) {
        Consumer<byte[]> responseConsumer = (bytes) -> {
            String responseData = new String(bytes, StandardCharsets.UTF_8);
            responseDataConsumer.ifPresent((rdc) -> rdc.accept(responseData));;
        };
        client.onBinaryMessage(responseConsumer);
    }

    private void registerTextResponseConsumer(Optional<Consumer<String>> responseDataConsumer, RemoteEndpoint client) {
        Consumer<String> responseConsumer = (string) -> {
                responseDataConsumer.ifPresent((rdc) -> rdc.accept(string));;
        };
        client.onStringMessage(responseConsumer);
    }

    private RemoteEndpoint initializeDefault(String name) {

        Consumer<Session> onOpen = (session) -> {
            log.info("Client connection opened for {}.", name);
        };

        Consumer<CloseReason> onClose = (closeReason) -> {
            log.info("Client connection closed for {}. {}", name, closeReason);
        };

        Consumer<Throwable> onError = (throwable) -> {
            if (!closed.get()) {
                log.error("An error occurred in websocket client for " + name, throwable);
            } else {
                log.trace("An error occurred in websocket client for " + name, throwable);
            }
        };
        RemoteEndpoint client = new RemoteEndpoint(onOpen, onClose, onError);

        return client;
    }

    @Override
    public void close() throws IOException {
        if(closed.compareAndSet(false, true)) {
            try {
                super.close();
                commandExecutingEndpoint.close();
                statusUpdatesEndpoint.close();
            } catch (Exception e) {
                log.error("Cannot close client.", e);
            }
        } else {
            log.debug("Already closed.");
        }
    }
}
