package org.jboss.pnc.buildagent.api.httpinvoke;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@JsonDeserialize(builder = Cancel.Builder.class)
public class Cancel {

    private final String sessionId;

    public Cancel(String sessionId) {
        this.sessionId = sessionId;
    }

    private Cancel(Builder builder) {
        sessionId = builder.sessionId;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public String getSessionId() {
        return sessionId;
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static final class Builder {

        private String sessionId;

        private Builder() {
        }

        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Cancel build() {
            return new Cancel(this);
        }
    }
}
