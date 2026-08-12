package org.jboss.pnc.buildagent.client;

import java.util.List;

import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.api.httpinvoke.RetryConfig;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public abstract class ClientConfigurationBase {

    protected String termBaseUrl;

    /**
     * Liveness response timeout in milliseconds.
     */
    protected long livenessResponseTimeout;

    protected RetryConfig retryConfig;
    protected List<Request.Header> requestHeaders;

    public String getTermBaseUrl() {
        return termBaseUrl;
    }

    public long getLivenessResponseTimeout() {
        return livenessResponseTimeout;
    }

    public RetryConfig getRetryConfig() {
        return retryConfig;
    }

    public List<Request.Header> getRequestHeaders() {
        return requestHeaders;
    }
}
