package org.jboss.pnc.buildagent.server;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * This DTO is used to map keycloak.json file to it so that we can do offline checking of tokens
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthHeaderFilterConfiguration {

    /**
     * The public key of the realm (realm-public-key), as specified in the {auth url}/auth/realms/{realm}
     */
    @JsonProperty("realm-public-key")
    private String realmPublicKey;

    /**
     * The auth server url: should be in format {auth url}/auth
     */
    @JsonProperty("auth-server-url")
    private String authServerUrl;

    @JsonProperty("ldap-host")
    private String ldapHost;

    @JsonProperty("ldap-port")
    private int ldapPort;

    @JsonProperty("ldap-search-base")
    private String ldapSearchBase;

    // needed for jackson
    public AuthHeaderFilterConfiguration() {
    }

    public AuthHeaderFilterConfiguration(String publicKey, String authServerUrl, String ldapHost, int ldapPort, String ldapSearchBase) {
        this.realmPublicKey = publicKey;
        this.authServerUrl = authServerUrl;
        this.ldapHost = ldapHost;
        this.ldapPort = ldapPort;
        this.ldapSearchBase = ldapSearchBase;
    }

    public String getRealmPublicKey() {
        return realmPublicKey;
    }

    public void setRealmPublicKey(String publicKey) {
        this.realmPublicKey = publicKey;
    }

    public String getAuthServerUrl() {
        return authServerUrl;
    }

    public void setAuthServerUrl(String authServerUrl) {
        this.authServerUrl = authServerUrl;
    }

    public String getLdapHost() {
        return ldapHost;
    }

    public void setLdapHost(String ldapHost) {
        this.ldapHost = ldapHost;
    }

    public int getLdapPort() {
        return ldapPort;
    }

    public void setLdapPort(int ldapPort) {
        this.ldapPort = ldapPort;
    }

    public String getLdapSearchBase() {
        return ldapSearchBase;
    }

    public void setLdapSearchBase(String ldapSearchBase) {
        this.ldapSearchBase = ldapSearchBase;
    }
}
