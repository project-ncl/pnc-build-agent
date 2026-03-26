package org.jboss.pnc.buildagent.server;

import io.undertow.servlet.api.InstanceFactory;
import io.undertow.servlet.api.InstanceHandle;
import io.undertow.servlet.util.ImmediateInstanceHandle;
import org.jboss.pnc.buildagent.api.httpinvoke.RetryConfig;
import org.jboss.pnc.buildagent.common.http.HttpClient;
import org.jboss.pnc.buildagent.common.http.HeartbeatSender;
import org.jboss.pnc.buildagent.common.security.KeycloakClient;
import org.jboss.pnc.buildagent.common.security.LdapClient;
import org.jboss.pnc.buildagent.server.httpinvoker.SessionRegistry;
import org.jboss.pnc.buildagent.server.servlet.HttpInvoker;

import java.security.NoSuchAlgorithmException;
import java.util.Set;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class HttpInvokerFactory implements InstanceFactory<HttpInvoker> {

    private final Set<ReadOnlyChannel> readOnlyChannels;

    private final SessionRegistry sessionRegistry;

    private final HttpClient httpClient;

    private final RetryConfig retryConfig;
    private final BifrostUploaderOptions bifrostUploaderOptions;
    private final HeartbeatSender heartbeat;

    private final KeycloakClient keycloakClient;
    private final LdapClient ldapClient;

    public HttpInvokerFactory(
            Set<ReadOnlyChannel> readOnlyChannels,
            HttpClient httpClient,
            SessionRegistry sessionRegistry,
            RetryConfig retryConfig,
            HeartbeatSender heartbeat,
            BifrostUploaderOptions bifrostUploaderOptions,
            KeycloakClient keycloakClient,
            LdapClient ldapClient) {
        this.readOnlyChannels = readOnlyChannels;
        this.httpClient = httpClient;
        this.sessionRegistry = sessionRegistry;
        this.retryConfig = retryConfig;
        this.bifrostUploaderOptions = bifrostUploaderOptions;
        this.heartbeat = heartbeat;
        this.keycloakClient = keycloakClient;
        this.ldapClient = ldapClient;
    }

    @Override
    public InstanceHandle<HttpInvoker> createInstance() throws InstantiationException {
        try {
            return new ImmediateInstanceHandle<>(new HttpInvoker(
                    readOnlyChannels,
                    sessionRegistry,
                    httpClient,
                    retryConfig,
                    heartbeat,
                    bifrostUploaderOptions,
                    keycloakClient,
                    ldapClient));
        } catch (NoSuchAlgorithmException e) {
            throw new InstantiationException("Cannot create HttpInvoker: " + e.getMessage());
        }
    }
}
