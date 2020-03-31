package org.jboss.pnc.buildagent.client;

import java.net.URL;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public class HttpClientConfiguration extends ClientConfigurationBase {
    private String callbackMethod;
    private URL callbackUrl;

    private HttpClientConfiguration(Builder builder) {
        termBaseUrl = builder.termBaseUrl;
        callbackMethod = builder.callbackMethod;
        callbackUrl = builder.callbackUrl;
        livenessResponseTimeout = builder.livenessResponseTimeout;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static Builder newBuilder(HttpClientConfiguration copy) {
        Builder builder = new Builder();
        builder.termBaseUrl = copy.getTermBaseUrl();
        builder.livenessResponseTimeout = copy.getLivenessResponseTimeout();
        builder.callbackMethod = copy.getCallbackMethod();
        builder.callbackUrl = copy.getCallbackUrl();
        return builder;
    }

    public String getCallbackMethod() {
        return callbackMethod;
    }

    public URL getCallbackUrl() {
        return callbackUrl;
    }

    public static final class Builder {
        private String termBaseUrl;
        private Long livenessResponseTimeout = 30000L;
        private String callbackMethod;
        private URL callbackUrl;

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

        public Builder callbackMethod(String callbackMethod) {
            this.callbackMethod = callbackMethod;
            return this;
        }

        public Builder callbackUrl(URL callbackUrl) {
            this.callbackUrl = callbackUrl;
            return this;
        }

        public HttpClientConfiguration build() {
            return new HttpClientConfiguration(this);
        }
    }
}
