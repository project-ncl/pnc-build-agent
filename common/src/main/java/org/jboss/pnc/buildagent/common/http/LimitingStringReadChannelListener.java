/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.jboss.pnc.buildagent.common.http;

import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xnio.ChannelListener;
import org.xnio.IoUtils;
import org.xnio.Pool;
import org.xnio.channels.StreamSourceChannel;

import io.undertow.connector.ByteBufferPool;
import io.undertow.connector.PooledByteBuffer;
import io.undertow.server.XnioByteBufferPool;
import io.undertow.websockets.core.UTF8Output;

/**
 * Based on {@link io.undertow.util.StringReadChannelListener}
 *
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public abstract class LimitingStringReadChannelListener implements ChannelListener<StreamSourceChannel> {

    private final static Logger logger = LoggerFactory.getLogger(LimitingStringReadChannelListener.class);

    private final UTF8Output string = new UTF8Output();
    private final ByteBufferPool bufferPool;
    private long maxDownloadSize;
    private long read = 0; //already read

    /**
     * @param bufferPool
     * @param maxDownloadSize max bytes to read, -1 for no limit. The result varies for the buffer size, maximum read
     *        bytes are readLimit + buffer.size.
     */
    public LimitingStringReadChannelListener(final ByteBufferPool bufferPool, long maxDownloadSize) {
        this.bufferPool = bufferPool;
        this.maxDownloadSize = maxDownloadSize;
    }

    /**
     * @param bufferPool
     * @param maxDownloadSize max bytes to read, -1 for no limit. The result varies for the buffer size, maximum read
     *        bytes are readLimit + buffer.size.
     */
    @Deprecated
    public LimitingStringReadChannelListener(final Pool<ByteBuffer> bufferPool, long maxDownloadSize) {
        this.bufferPool = new XnioByteBufferPool(bufferPool);
        this.maxDownloadSize = maxDownloadSize;
    }

    public void setup(final StreamSourceChannel channel) {
        PooledByteBuffer resource = bufferPool.allocate();
        ByteBuffer buffer = resource.getBuffer();
        try {
            int r = 0;
            do {
                r = channel.read(buffer);
                if (r == 0) {
                    channel.getReadSetter().set(this);
                    channel.resumeReads();
                } else if (r == -1) {
                    stringDone(new StringResult(true, string.extract()));
                    IoUtils.safeClose(channel);
                } else {
                    ((Buffer) buffer).flip();
                    string.write(buffer);
                    read += r;
                    if (maxDownloadSize > -1L) {
                        if (read > maxDownloadSize) {
                            stringDone(new StringResult(false, string.extract()));
                            IoUtils.safeClose(channel);
                            break;
                        } else if (read == maxDownloadSize) {
                            int readByte = channel.read(ByteBuffer.allocate(1));
                            if (readByte > -1) {
                                stringDone(new StringResult(false, string.extract()));
                            } else {
                                stringDone(new StringResult(true, string.extract()));
                            }
                            IoUtils.safeClose(channel);
                            break;
                        }
                    }
                }
            } while (r > 0);
        } catch (IOException e) {
            error(e);
        } finally {
            resource.close();
            logger.trace("Resource closed in setup.");
        }
    }

    @Override
    public void handleEvent(final StreamSourceChannel channel) {
        PooledByteBuffer resource = bufferPool.allocate();
        ByteBuffer buffer = resource.getBuffer();
        try {
            int r = 0;
            do {
                r = channel.read(buffer);
                if (r == 0) {
                    return;
                } else if (r == -1) {
                    stringDone(new StringResult(true, string.extract()));
                    IoUtils.safeClose(channel);
                } else {
                    ((Buffer) buffer).flip();
                    string.write(buffer);
                    read += r;
                    if (maxDownloadSize > -1L) {
                        if (read > maxDownloadSize) {
                            stringDone(new StringResult(false, string.extract()));
                            IoUtils.safeClose(channel);
                            break;
                        } else if (read == maxDownloadSize) {
                            int readByte = channel.read(ByteBuffer.allocate(1));
                            if (readByte > -1) {
                                stringDone(new StringResult(false, string.extract()));
                            } else {
                                stringDone(new StringResult(true, string.extract()));
                            }
                            IoUtils.safeClose(channel);
                            break;
                        }
                    }
                }
            } while (r > 0);
        } catch (IOException e) {
            error(e);
        } finally {
            resource.close();
            logger.trace("Resource closed in handleEvent.");
        }
    }

    protected abstract void stringDone(StringResult stringResult);

    protected abstract void error(IOException e);

}
