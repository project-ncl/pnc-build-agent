package org.jboss.pnc.buildagent.common.http;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;

import org.jboss.pnc.api.dto.HeartbeatConfig;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.common.concurrent.MDCScheduledThreadPoolExecutor;
import org.jboss.pnc.buildagent.common.concurrent.NamedThreadFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HeartbeatSender {

    private final Logger logger = LoggerFactory.getLogger(HeartbeatSender.class);

    private final ScheduledExecutorService executor;
    private final HttpClient httpClient;

    private final HeartbeatHttpHeaderProvider heartbeatHttpHeaderProvider;

    public HeartbeatSender(HttpClient httpClient) {
        this(httpClient, null);
    }

    /**
     * The HeartbeatHttpHeaderProvider provides a way to inject additional Http headers on each heartbeat sent.
     * This is useful for adding authorization headers whose values will change dynamically as new access tokens are
     * obtained.
     *
     * @param httpClient http client to use
     * @param heartbeatHttpHeaderProvider interface to add more headers to each heartbeat sent
     */
    public HeartbeatSender(HttpClient httpClient, HeartbeatHttpHeaderProvider heartbeatHttpHeaderProvider) {
        this.httpClient = httpClient;
        this.heartbeatHttpHeaderProvider = heartbeatHttpHeaderProvider;
        executor = new MDCScheduledThreadPoolExecutor(1, new NamedThreadFactory("heartbeat"));
    }

    public Future<?> start(HeartbeatConfig heartbeatConfig) {
        return executor.scheduleAtFixedRate(
                () -> sendHeartbeat(heartbeatConfig.getRequest()),
                0L,
                heartbeatConfig.getDelay(),
                heartbeatConfig.getDelayTimeUnit());
    }

    public void stop(Future<?> heartBeatFuture) {
        heartBeatFuture.cancel(false);
    }

    private void sendHeartbeat(Request heartbeatRequest) {
        httpClient.invoke(addHeartbeatHttpHeader(heartbeatRequest), ByteBuffer.allocate(0), 0, 0L, -1L, 0, 0)
                .handle((response, throwable) -> {
                    if (throwable != null) {
                        logger.error("Cannot send heartbeat.", throwable);
                    } else {
                        logger.info("Heartbeat sent.");
                    }
                    return null;
                });
    }

    private Request addHeartbeatHttpHeader(Request original) {

        List<Request.Header> headers = new ArrayList<>(original.getHeaders());
        if (heartbeatHttpHeaderProvider != null) {
            logger.info("Adding additional http headers to heartbeat");
            headers.addAll(heartbeatHttpHeaderProvider.getHeaders());
        }
        return new Request(original.getMethod(), original.getUri(), headers, original.getAttachment());
    }

}
