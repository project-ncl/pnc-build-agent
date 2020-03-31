package org.jboss.pnc.buildagent.client;

import org.jboss.pnc.buildagent.api.ResponseMode;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public class SocketClientConfiguration extends ClientConfigurationBase {

    private ResponseMode responseMode;
    private boolean readOnly;
    private String commandContext;

    private SocketClientConfiguration(Builder builder) {
        termBaseUrl = builder.termBaseUrl;
        responseMode = builder.responseMode;
        readOnly = builder.readOnly;
        livenessResponseTimeout = builder.livenessResponseTimeout;
        commandContext = builder.commandContext;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static Builder newBuilder(SocketClientConfiguration copy) {
        Builder builder = new Builder();
        builder.termBaseUrl = copy.getTermBaseUrl();
        builder.livenessResponseTimeout = copy.getLivenessResponseTimeout();
        builder.responseMode = copy.getResponseMode();
        builder.readOnly = copy.isReadOnly();
        builder.commandContext = copy.getCommandContext();
        return builder;
    }

    public ResponseMode getResponseMode() {
        return responseMode;
    }

    public boolean isReadOnly() {
        return readOnly;
    }

    public String getCommandContext() {
        return commandContext;
    }

    public static final class Builder {
        private String termBaseUrl;
        private Long livenessResponseTimeout = 30000L;
        private ResponseMode responseMode = ResponseMode.SILENT;
        private boolean readOnly = false;
        private String commandContext = "";

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

        public Builder responseMode(ResponseMode responseMode) {
            this.responseMode = responseMode;
            return this;
        }

        public Builder readOnly(boolean readOnly) {
            this.readOnly = readOnly;
            return this;
        }

        public Builder commandContext(String commandContext) {
            this.commandContext = commandContext;
            return this;
        }

        public SocketClientConfiguration build() {
            return new SocketClientConfiguration(this);
        }
    }
}
