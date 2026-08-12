package org.jboss.pnc.buildagent.client;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.jboss.pnc.api.dto.HeartbeatConfig;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.api.httpinvoke.RetryConfig;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public class HttpClientConfiguration extends ClientConfigurationBase {

    private Request callback;
    private Optional<HeartbeatConfig> heartbeatConfig;

    private HttpClientConfiguration(Builder builder) {
        termBaseUrl = builder.termBaseUrl;
        livenessResponseTimeout = builder.livenessResponseTimeout;
        callback = builder.callback;
        retryConfig = builder.retryConfig;
        heartbeatConfig = builder.heartbeatConfig;
        requestHeaders = builder.requestHeaders;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static Builder newBuilder(HttpClientConfiguration copy) {
        Builder builder = new Builder();
        builder.termBaseUrl = copy.getTermBaseUrl();
        builder.livenessResponseTimeout = copy.getLivenessResponseTimeout();
        builder.callback = copy.getCallback();
        builder.retryConfig = copy.getRetryConfig();
        builder.heartbeatConfig = copy.getHeartbeatConfig();
        builder.requestHeaders = copy.getRequestHeaders();
        return builder;
    }

    public Request getCallback() {
        return callback;
    }

    public Optional<HeartbeatConfig> getHeartbeatConfig() {
        return heartbeatConfig;
    }

    public static final class Builder {
        private String termBaseUrl;
        private Long livenessResponseTimeout = 30000L;
        private Request callback;
        public Optional<HeartbeatConfig> heartbeatConfig = Optional.empty();
        private RetryConfig retryConfig = new RetryConfig(10, 500L);
        private List<Request.Header> requestHeaders = Collections.emptyList();

        private Builder() {
        }

        public Builder termBaseUrl(String termBaseUrl) {
            this.termBaseUrl = termBaseUrl;
            return this;
        }

        public Builder livenessResponseTimeout(long livenessResponseTimeout) {
            this.livenessResponseTimeout = livenessResponseTimeout;
            return this;
        }

        public Builder callback(Request callback) {
            this.callback = callback;
            return this;
        }

        public Builder heartbeatConfig(Optional<HeartbeatConfig> heartbeatConfig) {
            this.heartbeatConfig = heartbeatConfig;
            return this;
        }

        public Builder retryConfig(RetryConfig retryConfig) {
            this.retryConfig = retryConfig;
            return this;
        }

        public Builder requestHeaders(List<Request.Header> requestHeaders) {
            this.requestHeaders = requestHeaders;
            return this;
        }

        public HttpClientConfiguration build() {
            return new HttpClientConfiguration(this);
        }
    }
}
