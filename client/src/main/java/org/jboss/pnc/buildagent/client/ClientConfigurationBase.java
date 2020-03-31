package org.jboss.pnc.buildagent.client;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public abstract class ClientConfigurationBase {

    protected String termBaseUrl;

    /**
     * Liveness response timeout in milliseconds.
     */
    protected long livenessResponseTimeout;

    public String getTermBaseUrl() {
        return termBaseUrl;
    }

    public long getLivenessResponseTimeout() {
        return livenessResponseTimeout;
    }
}
