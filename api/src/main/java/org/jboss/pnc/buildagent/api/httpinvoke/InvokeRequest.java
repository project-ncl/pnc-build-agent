package org.jboss.pnc.buildagent.api.httpinvoke;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;

import org.jboss.pnc.api.dto.HeartbeatConfig;
import org.jboss.pnc.api.dto.Request;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@JsonDeserialize(builder = InvokeRequest.Builder.class)
public class InvokeRequest {

    private final String command;

    /**
     * Callback request
     */
    private final Request callback;

    private final HeartbeatConfig heartbeatConfig;

    /**
     * @deprecated use {@link InvokeRequest(String, Request )}
     */
    @Deprecated
    public InvokeRequest(String command, URL callbackUrl, String callbackMethod) {
        this.command = command;
        heartbeatConfig = null;
        try {
            this.callback = new Request(
                    Request.Method.valueOf(callbackMethod),
                    callbackUrl.toURI(),
                    Collections.emptyList());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public InvokeRequest(String command, Request callback) {
        this.command = command;
        this.callback = callback;
        heartbeatConfig = null;
    }

    public InvokeRequest(String command, Request callback, HeartbeatConfig heartbeatConfig) {
        this.command = command;
        this.callback = callback;
        this.heartbeatConfig = heartbeatConfig;
    }

    private InvokeRequest(Builder builder) {
        command = builder.command;
        callback = builder.callback;
        heartbeatConfig = builder.heartbeatConfig;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getCommand() {
        return command;
    }

    public Request getCallback() {
        return callback;
    }

    public HeartbeatConfig getHeartbeatConfig() {
        return heartbeatConfig;
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static final class Builder {

        private String command;

        private Request callback;

        private HeartbeatConfig heartbeatConfig;

        private Builder() {
        }

        public Builder command(String command) {
            this.command = command;
            return this;
        }

        public Builder callback(Request callback) {
            this.callback = callback;
            return this;
        }

        public Builder heartbeatConfig(HeartbeatConfig heartbeatConfig) {
            this.heartbeatConfig = heartbeatConfig;
            return this;
        }

        public InvokeRequest build() {
            return new InvokeRequest(this);
        }
    }
}
