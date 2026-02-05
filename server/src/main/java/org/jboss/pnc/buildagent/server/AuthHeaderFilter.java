package org.jboss.pnc.buildagent.server;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * Alternative implementation of KeycloakOIDCFilter, which does not use the .well-known/openid-configuration endpoint
 * and instead validates the authentication token offline using jjwt and the provided realm-public-key
 */
public class AuthHeaderFilter implements Filter {

    public final static String AUTH_HEADER_PARAM = "auth-header-param.file";

    private final static Logger log = Logger.getLogger("" + AuthHeaderFilter.class);
    private AuthHeaderFilterConfiguration configuration;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);

        String fp = filterConfig.getInitParameter(AUTH_HEADER_PARAM);
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            configuration = objectMapper.readValue(new File(fp), AuthHeaderFilterConfiguration.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        String authHeader = request.getHeader("Authorization").trim();

        if (authHeader.startsWith("Bearer")) {
            // OIDC Authentication
            String authToken = authHeader.replace("Bearer", "").trim();
            try {
                OidcOfflineTokenVerifier.verify(authToken, configuration.getRealmPublicKey(), configuration.getAuthServerUrl());

                // all good, no exceptions thrown.
                filterChain.doFilter(req, res);
                return;
            } catch (Exception e) {
                log.warning("Authorization using OIDC failed with error: " + e);
                response.sendError(403);
                return;
            }
        } else if (authHeader.startsWith("Basic")) {
            // Basic LDAP authentication: values is <username>:<password> base64 encoded. so we need to do the reverse
            // to extract the username and password
            String base64EncodedValue = authHeader.replace("Basic", "").trim();
            String usernameAndPassword = new String(Base64.getDecoder().decode(base64EncodedValue), StandardCharsets.UTF_8);
            String[] splitUsernameAndPassword = usernameAndPassword.split(":");

            String username;
            String password;
            if (splitUsernameAndPassword.length == 2) {
                username = splitUsernameAndPassword[0];
                password = splitUsernameAndPassword[1];
            } else {
                log.warning("Authorization using LDAP failed with malformed auth header value");
                response.sendError(403);
                return;
            }
            boolean verified = LdapVerifier.verifyUser(
                    configuration.getLdapHost(),
                    configuration.getLdapPort(),
                    username,
                    password,
                    configuration.getLdapSearchBase());

            if (verified) {
                filterChain.doFilter(req, res);
            } else {
                log.warning("Authorization using LDAP failed");
                response.sendError(403);
            }
            return;
        }
    }


    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
