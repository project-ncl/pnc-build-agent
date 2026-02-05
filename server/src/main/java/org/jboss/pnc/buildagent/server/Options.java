package org.jboss.pnc.buildagent.server;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class Options {

    private final String host;
    private final int port;
    private final String bindPath;

    private final boolean socketInvokerEnabled;
    private final boolean httpInvokerEnabled;
    private final int callbackMaxRetries;
    private final long callbackWaitBeforeRetry;
    private final String authHeaderConfigFile;

    private final String keycloakClientConfigFile;
    private final int httpReadTimeout;
    private final int httpWriteTimeout;

    private final BifrostUploaderOptions bifrostUploaderOptions;

    public Options(
        String host,
        int bindPort,
        String bindPath,
        boolean socketInvokerEnabled,
        boolean httpInvokerEnabled,
        int callbackMaxRetries,
        long callbackWaitBeforeRetry,
        BifrostUploaderOptions bifrostUploaderOptions,
        String authHeaderConfigFile,
        String keycloakClientConfigFile,
        int httpReadTimeout,
        int httpWriteTimeout) {
        this.host = host;
        this.bindPath = bindPath;
        this.socketInvokerEnabled = socketInvokerEnabled;
        this.httpInvokerEnabled = httpInvokerEnabled;
        this.callbackMaxRetries = callbackMaxRetries;
        this.callbackWaitBeforeRetry = callbackWaitBeforeRetry;
        this.bifrostUploaderOptions = bifrostUploaderOptions;
        this.authHeaderConfigFile = authHeaderConfigFile;
        this.keycloakClientConfigFile = keycloakClientConfigFile;
        this.httpReadTimeout = httpReadTimeout;
        this.httpWriteTimeout = httpWriteTimeout;

        if (bindPort == 0) {
            port = findFirstFreePort();
        } else {
            port = bindPort;
        }
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getBindPath() {
        return bindPath;
    }

    public boolean isHttpInvokerEnabled() {
        return httpInvokerEnabled;
    }

    public boolean isSocketInvokerEnabled() {
        return socketInvokerEnabled;
    }

    private int findFirstFreePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not obtain default port, try specifying it explicitly");
        }
    }

    public int getCallbackMaxRetries() {
        return callbackMaxRetries;
    }

    public long getCallbackWaitBeforeRetry() {
        return callbackWaitBeforeRetry;
    }

    public String getAuthHeaderConfigFile() {
        return authHeaderConfigFile;
    }

    public String getKeycloakClientConfigFile() {
        return keycloakClientConfigFile;
    }

    public int getHttpReadTimeout() {
        return httpReadTimeout;
    }

    public int getHttpWriteTimeout() {
        return httpWriteTimeout;
    }

    public BifrostUploaderOptions getBifrostUploaderOptions() {
        return bifrostUploaderOptions;
    }

}
