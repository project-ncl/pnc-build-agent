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

import java.io.IOException;
import java.nio.ByteBuffer;

import org.jboss.pnc.buildagent.server.ReadOnlyChannel;

import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.WebSockets;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class ReadOnlyWebSocketChannel implements ReadOnlyChannel {

    private WebSocketChannel webSocketChannel;

    public ReadOnlyWebSocketChannel(WebSocketChannel webSocketChannel) {
        this.webSocketChannel = webSocketChannel;
    }

    @Override
    public void writeOutput(byte[] buffer) {
        WebSockets.sendBinary(ByteBuffer.wrap(buffer), webSocketChannel, null);
    }

    @Override
    public boolean isPrimary() {
        return false;
    }

    @Override
    public void flush() throws IOException {
        webSocketChannel.flush();
    }

    @Override
    public void close() throws IOException {
        webSocketChannel.sendClose();
    }
}
