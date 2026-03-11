package org.jboss.pnc.buildagent.server.termserver;

import org.jboss.pnc.api.constants.HttpHeaders;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.common.http.HeartbeatHttpHeaderProvider;
import org.jboss.pnc.buildagent.common.security.KeycloakClient;
import org.jboss.pnc.buildagent.common.security.LdapClient;

import java.util.Collections;
import java.util.List;

/**
 * Implementation of HeartbeathttpHeaderProvider that uses either the ldap Client or our own
 * Keycloak client to inject a new access token on each heartbeat sent
 */
public class GeneralHeartbeatHttpHeaderProvider implements HeartbeatHttpHeaderProvider {

    private final KeycloakClient keycloakClient;
    private final LdapClient ldapClient;

    public GeneralHeartbeatHttpHeaderProvider(KeycloakClient keycloakClient, LdapClient ldapClient) {
       this.keycloakClient = keycloakClient;
       this.ldapClient = ldapClient;
    }
    @Override
    public List<Request.Header> getHeaders() {
        if (ldapClient != null) {
            return Collections.singletonList(new Request.Header(HttpHeaders.AUTHORIZATION_STRING, ldapClient.getBasicAuthHeaderValue()));
        } else if (keycloakClient != null) {
            return Collections.singletonList(new Request.Header(HttpHeaders.AUTHORIZATION_STRING, keycloakClient.getBearerAccessToken()));
        } else  {
            return Collections.EMPTY_LIST;
        }
    }
}
