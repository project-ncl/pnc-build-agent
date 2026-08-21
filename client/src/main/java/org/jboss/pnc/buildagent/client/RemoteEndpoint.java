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

import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

import javax.websocket.CloseReason;
import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;

import org.jboss.pnc.buildagent.api.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @see "https://github.com/undertow-io/undertow/blob/5bdddf327209a4abf18792e78148863686c26e9b/websockets-jsr/src/test/java/io/undertow/websockets/jsr/test/BinaryEndpointTest.java"
 *
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class RemoteEndpoint extends Endpoint {

    public static final String WEB_SOCKET_TERMINAL_PATH = Constants.SOCKET_PATH + Constants.TERM_PATH;
    public static final String WEB_SOCKET_TERMINAL_TEXT_PATH = Constants.SOCKET_PATH + Constants.TERM_PATH_TEXT;
    public static final String WEB_SOCKET_TERMINAL_SILENT_PATH = Constants.SOCKET_PATH + Constants.TERM_PATH_SILENT;
    public static final String WEB_SOCKET_LISTENER_PATH = Constants.SOCKET_PATH + Constants.PROCESS_UPDATES_PATH;

    private static final Logger log = LoggerFactory.getLogger(RemoteEndpoint.class);

    private volatile Session session;

    private Consumer<Session> onOpenConsumer;
    private Consumer<String> onStringMessageConsumer;
    private Consumer<byte[]> onBinaryMessageConsumer;
    private Consumer<CloseReason> onCloseConsumer;
    private Consumer<Throwable> onErrorConsumer;

    public RemoteEndpoint(
            Consumer<Session> onOpenConsumer,
            Consumer<CloseReason> onCloseConsumer,
            Consumer<Throwable> onErrorConsumer) {
        this.onOpenConsumer = onOpenConsumer;
        this.onCloseConsumer = onCloseConsumer;
        this.onErrorConsumer = onErrorConsumer;
    }

    public void close() throws Exception {
        log.debug("Client is closing connection.");
        session.close();
    }

    public void onOpen(Consumer<Session> onOpen) {
        onOpenConsumer = onOpen;
    }

    public void onStringMessage(Consumer<String> onStringMessage) {
        onStringMessageConsumer = onStringMessage;
    }

    public void onBinaryMessage(Consumer<byte[]> onBinaryMessage) {
        onBinaryMessageConsumer = onBinaryMessage;
    }

    public javax.websocket.RemoteEndpoint.Async getRemoteEndpoint() {
        return session.getAsyncRemote();
    }

    @Override
    public void onOpen(Session session, EndpointConfig config) {
        log.debug("Client received open.");
        this.session = session;

        session.addMessageHandler(new MessageHandler.Whole<String>() {
            @Override
            public void onMessage(String message) {
                log.trace("Client received text MESSAGE: {}", message);
                if (onStringMessageConsumer != null) {
                    onStringMessageConsumer.accept(message);
                }
            }
        });
        session.addMessageHandler(new MessageHandler.Whole<byte[]>() {
            @Override
            public void onMessage(byte[] bytes) {
                log.trace(
                        "Client received binary MESSAGE: [{}]. Raw bytes [{}].",
                        new String(bytes, StandardCharsets.UTF_8),
                        bytes);
                if (onBinaryMessageConsumer != null) {
                    onBinaryMessageConsumer.accept(bytes);
                }
            }
        });
        if (onOpenConsumer != null) {
            onOpenConsumer.accept(session);
        }
    }

    @Override
    public void onClose(Session session, CloseReason closeReason) {
        log.debug("Client received close. CloseReason {}.", closeReason);
        onCloseConsumer.accept(closeReason);
    }

    @Override
    public void onError(Session session, Throwable thr) {
        if (onErrorConsumer != null) {
            onErrorConsumer.accept(thr);
        } else {
            log.error("No error handler defined. Received error was: ", thr);
        }
    }
}
