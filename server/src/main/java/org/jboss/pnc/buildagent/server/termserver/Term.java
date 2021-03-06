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

package org.jboss.pnc.buildagent.server.termserver;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.termd.core.pty.PtyMaster;
import io.termd.core.pty.Status;
import io.termd.core.pty.TtyBridge;
import io.undertow.server.HttpHandler;
import io.undertow.websockets.WebSocketConnectionCallback;
import io.undertow.websockets.WebSocketProtocolHandshakeHandler;
import io.undertow.websockets.core.CloseMessage;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.WebSockets;
import org.jboss.pnc.buildagent.api.ResponseMode;
import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.jboss.pnc.buildagent.common.Arrays;
import org.jboss.pnc.buildagent.common.function.ThrowingConsumer;
import org.jboss.pnc.buildagent.common.security.Md5;
import org.jboss.pnc.buildagent.server.ReadOnlyChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class Term {

    private Logger log = LoggerFactory.getLogger(Term.class);

    final String context;
    private Runnable onDestroy;
    final Set<TaskStatusUpdateListener> statusUpdateListeners = new CopyOnWriteArraySet<>();
    private WebSocketTtyConnection webSocketTtyConnection;
    private boolean activeCommand;

    CompleteHandler completeHandle = new CompleteHandler();
    private Md5 stdoutChecksum;


    private final Set<ReadOnlyChannel> readOnlyChannels = new CopyOnWriteArraySet<>();

    public Term(String context, Runnable onDestroy, ScheduledExecutorService executor, Set<ReadOnlyChannel> readOnlyChannels) {
        this.context = context;
        this.onDestroy = onDestroy;
        this.readOnlyChannels.addAll(readOnlyChannels);

        Runnable onStdOutCompleted = () -> {
            completeHandle.setStdoutCompletedAndRun();
        };
        webSocketTtyConnection = new WebSocketTtyConnection(executor, onStdOutCompleted);
        try {
            stdoutChecksum = new Md5();
        } catch (NoSuchAlgorithmException e) {
            log.error("Cannot instantiate new Term.", e);
        }
        log.debug("Created new Term: {}.", this);
    }

    private volatile Boolean ttyBridgeInitialized = false;

    private void initializeTtyBridge() {
        synchronized (this) {
            if (!ttyBridgeInitialized) {
                TtyBridge ttyBridge = new TtyBridge(webSocketTtyConnection);
                ttyBridge
                    .setProcessListener(onTaskCreated())
                    .setProcessStdoutListener(ints -> onStdOut(ints))
                    .setProcessStdinListener((commandLine) -> {
                        log.debug("New command received: {}", commandLine);
                        onStdIn(commandLine);
                    })
                    .readline();
                ttyBridgeInitialized = true;
            }
        }
    }

    public void addStatusUpdateListener(TaskStatusUpdateListener statusUpdateListener) {
        statusUpdateListeners.add(statusUpdateListener);
    }

    public void removeStatusUpdateListener(TaskStatusUpdateListener statusUpdateListener) {
        statusUpdateListeners.remove(statusUpdateListener);
    }

    public Consumer<PtyMaster> onTaskCreated() {
        return (ptyMaster) -> {
            ptyMaster.setChangeHandler((oldStatus, newStatus) -> {
                String logDigest;
                if (newStatus.isFinal()) {
                    writeCompletedToReadonlyChannel(newStatus);
                    logDigest = stdoutChecksum.digest();
                } else {
                    logDigest = "";
                }
                notifyStatusUpdated(
                        new TaskStatusUpdateEvent(
                                "" + ptyMaster.getId(),
                                StatusConverter.fromTermdStatus(oldStatus),
                                StatusConverter.fromTermdStatus(newStatus),
                                context,
                                logDigest)
                );
            });
        };
    }

    void notifyStatusUpdated(TaskStatusUpdateEvent event) {
        if (event.getNewStatus().isFinal()) {
            activeCommand = false;
            log.debug("Command [context:{} taskId:{}] execution completed with status {}.", event.getContext(), event.getTaskId(), event.getNewStatus());

            try {
                readOnlyChannels.stream()
                        .filter(ch -> ch.isPrimary())
                        .forEach(ThrowingConsumer.wrap(ch -> ch.flush()));
            } catch (Exception e) {
                log.error("Cannot flush primary RO channel.", e);
                event = TaskStatusUpdateEvent.newBuilder()
                        .taskId(event.getTaskId())
                        .newStatus(org.jboss.pnc.buildagent.api.Status.SYSTEM_ERROR)
                        .message("Cannot flush primary RO channel. " + e.getMessage())
                        .build();
            }
            completeHandle.setCompletionEventAndRun(event);
        } else {
            log.debug("Setting command active flag [context:{} taskId:{}] Notifying status {}.", event.getContext(), event.getTaskId(), event.getNewStatus());
            activeCommand = true;
            completeHandle.reset();
            //notify only for non final statuses, final status have to wait for log completion. Is called in #complete
            notifyStatusUpdateListeners(event);
        }
    }

    private void complete(TaskStatusUpdateEvent event) {
        destroyIfInactiveAndDisconnected();
        notifyStatusUpdateListeners(event);
    }

    private void notifyStatusUpdateListeners(TaskStatusUpdateEvent event) {
        for (TaskStatusUpdateListener statusUpdateListener : statusUpdateListeners) {
            log.debug("Notifying listener {} in task {} with new status {}", statusUpdateListener, event.getTaskId(), event.getNewStatus());
            statusUpdateListener.getEventConsumer().accept(event);
        }
    }

    private void writeCompletedToReadonlyChannel(Status newStatus) {
        String completed = "% # Command finished with status: " + newStatus + "\n";
        writeToChannels(completed.getBytes(StandardCharsets.UTF_8));
    }

    private void destroyIfInactiveAndDisconnected() {
        if (!activeCommand && !webSocketTtyConnection.isOpen()) {
            log.info("Destroying Term as there is no running command and no active connection.");
            onDestroy.run();
        }
    }

    public HttpHandler getWebSocketHandler(ResponseMode responseMode, boolean readOnly) {
        WebSocketConnectionCallback onWebSocketConnected = (exchange, webSocketChannel) -> {
            if (!readOnly) {
                if (webSocketTtyConnection.isOpen()) {
                    rejectDueToAlreadyActive(webSocketChannel);
                    return;
                }
                log.info("Adding new master connection from remote address {} to context [{}].", webSocketChannel.getSourceAddress().toString(), context);
                webSocketTtyConnection.setWebSocketChannel(webSocketChannel, responseMode);
                webSocketChannel.addCloseTask((task) -> {
                    log.debug("Master connection closed.");
                    webSocketTtyConnection.removeWebSocketChannel();
                    destroyIfInactiveAndDisconnected();
                });
                initializeTtyBridge();
            } else {
                ReadOnlyChannel readOnlyChannel;
                if (responseMode.equals(ResponseMode.TEXT)) {
                    log.info("Adding new readonly text consumer connection from remote address {} to context [{}].", webSocketChannel.getSourceAddress().toString(), context);
                    readOnlyChannel = new ReadOnlyWebSocketTextChannel(webSocketChannel);
                } else {
                    log.info("Adding new readonly binary consumer connection from remote address {} to context [{}].", webSocketChannel.getSourceAddress().toString(), context);
                    readOnlyChannel = new ReadOnlyWebSocketChannel(webSocketChannel);
                }
                readOnlyChannels.add(readOnlyChannel);
                webSocketChannel.addCloseTask((task) -> {
                    log.debug("Removing RO channel: {}.", readOnlyChannel);
                    readOnlyChannels.remove(readOnlyChannel);
                    destroyIfInactiveAndDisconnected();
                });
            }
        };
        return new WebSocketProtocolHandshakeHandler(onWebSocketConnected);
    }

    public HttpHandler webSocketStatusUpdateHandler() {
        WebSocketConnectionCallback webSocketConnectionCallback = (exchange, webSocketChannel) -> {
            Consumer<TaskStatusUpdateEvent> eventConsumer = event -> {
                Map<String, Object> statusUpdate = new HashMap<>();
                statusUpdate.put("action", "status-update");
                statusUpdate.put("event", event);

                ObjectMapper objectMapper = new ObjectMapper();
                try {
                    String message = objectMapper.writeValueAsString(statusUpdate);
                    WebSockets.sendText(message, webSocketChannel, null);
                } catch (JsonProcessingException e) {
                    log.error("Cannot write object to JSON", e);
                    String errorMessage = "Cannot write object to JSON: " + e.getMessage();
                    WebSockets.sendClose(CloseMessage.UNEXPECTED_ERROR, errorMessage, webSocketChannel, null);
                }
            };
            TaskStatusUpdateListener statusUpdateListener = new TaskStatusUpdateListener(eventConsumer, webSocketChannel);
            log.debug("Registering new status update listener {}.", statusUpdateListener);
            addStatusUpdateListener(statusUpdateListener);
            webSocketChannel.addCloseTask((task) -> removeStatusUpdateListener(statusUpdateListener));
        };

        return new WebSocketProtocolHandshakeHandler(webSocketConnectionCallback);
    }

    private void rejectDueToAlreadyActive(WebSocketChannel webSocketChannel) {
        log.info("Closing connection because there is already active master connection.");
        webSocketChannel.setCloseReason("Already active master connection.");
        try {
            webSocketChannel.sendClose();
        } catch (IOException e) {
            log.warn("Cannot reject connection.", e);
        }
    }

    private void onStdIn(String stdIn) {
        byte[] bytes = stdIn.getBytes();
        writeToChannels(bytes);
    }

    private void onStdOut(int[] stdOut) {
        byte[] buffer = Arrays.charIntstoBytes(stdOut, StandardCharsets.UTF_8);
        writeToChannels(buffer);
    }

    private void writeToChannels(byte[] bytes) {
        stdoutChecksum.add(bytes);
        if (log.isTraceEnabled()) {
            log.trace("Writing data: {}", new String(bytes, StandardCharsets.UTF_8));
        }
        for (ReadOnlyChannel readOnlyChannel : readOnlyChannels) {
            if (log.isTraceEnabled()) {
                log.trace("   to chanel {}", readOnlyChannel);
            }
            readOnlyChannel.writeOutput(bytes);
        }
    }

    public void close() {
        log.info("Closing Term {}.", context);
        webSocketTtyConnection.close();
    }

    private class CompleteHandler {
        boolean stdoutCompleted;
        TaskStatusUpdateEvent completionEvent;

        public synchronized void setStdoutCompletedAndRun() {
            stdoutCompleted = true;
            log.debug("Stdout completed, trying to run complete ...");
            run();
        }

        public synchronized void setCompletionEventAndRun(TaskStatusUpdateEvent completionEvent) {
            this.completionEvent = completionEvent;
            log.debug("Completion event received, trying to run complete ...");
            run();
        }

        private synchronized void run() {
            if (completionEvent != null && stdoutCompleted) {
                log.debug("Completing operation...");
                complete(completionEvent);
            }
        }

        public synchronized void reset() {
            log.debug("Resetting CompleteHandler...");
            stdoutCompleted = false;
            completionEvent = null;
        }
    }

}
