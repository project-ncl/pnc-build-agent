package org.jboss.pnc.buildagent.server.termserver;

import org.jboss.pnc.api.constants.HttpHeaders;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.common.http.HeartbeatHttpHeaderProvider;
import org.jboss.pnc.buildagent.common.security.KeycloakClient;

import java.util.Collections;
import java.util.List;

/**
 * Implementation of HeartbeathttpHeaderProvider that uses our own Keycloak client to inject a new access token on each
 * heartbeat sent
 */
public class KeycloakHeartbeatHttpHeaderProvider implements HeartbeatHttpHeaderProvider {

    private final KeycloakClient keycloakClient;

    public KeycloakHeartbeatHttpHeaderProvider(KeycloakClient keycloakClient) {
       this.keycloakClient = keycloakClient;
    }
    @Override
    public List<Request.Header> getHeaders() {
        if (keycloakClient == null) {
            return Collections.emptyList();
        } else {
            return Collections.singletonList(new Request.Header(HttpHeaders.AUTHORIZATION_STRING, keycloakClient.getBearerAccessToken()));
        }
    }
}
