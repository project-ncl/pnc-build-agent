package org.jboss.pnc.buildagent.server;

import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.ssl.SSLUtil;

import javax.net.ssl.SSLSocketFactory;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

/**
 * Class to verify whether the ldap username and password is valid
 */
public class LdapVerifier {

    private final static Logger log = Logger.getLogger("" + LdapVerifier.class);

    /**
     * Verify whether the username and password is valid, given the LDAP information
     * @param hostLdapServer ldap server (assumes we are using ldaps)
     * @param portLdapServer ldap port (usually 636)
     * @param username username to verify
     * @param password password to verify
     * @param searchBase searchBaseDn filter for the user
     * @return whether the user credentials is valid or not
     */
    public static boolean verifyUser(
            String hostLdapServer,
            int portLdapServer,
            String username,
            String password,
            String searchBase) {

        SSLUtil sslUtil = null;
        SSLSocketFactory socketFactory = null;
        try {
            sslUtil = new SSLUtil();
            socketFactory = sslUtil.createSSLSocketFactory();
        } catch (GeneralSecurityException e) {
            log.severe(e.getMessage());
            return false;
        }

        // Step 1: Connect as Service Account
        try (LDAPConnection conn = new LDAPConnection(socketFactory, hostLdapServer, portLdapServer)) {

            // Step 2: Search for the user to get their full DN
            // Filter.createEqualityFilter handles escaping automatically (prevents injection)
            Filter filter = Filter.createEqualityFilter("mail", username);
            SearchRequest searchRequest = new SearchRequest(searchBase, SearchScope.SUB, filter, "1.1"); // "1.1" means return no attributes

            SearchResult result = conn.search(searchRequest);

            if (result.getEntryCount() != 1) {
                System.out.println("entry count is weird: " + result.getEntryCount());
            }

            String userDN = result.getSearchEntries().get(0).getDN();

            // Step 3: Attempt to bind with the actual user's credentials
            // We create a new connection to avoid changing the state of the service connection
            try (LDAPConnection userConn = new LDAPConnection(socketFactory, hostLdapServer, portLdapServer)) {
                BindResult bindResult = userConn.bind(userDN, password);
                if (bindResult.getResultCode() == ResultCode.SUCCESS) {
                    return true;
                }
            } catch (LDAPException e) {
                if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS) {
                    return false;
                }
            }
        } catch (LDAPException e) {
            log.severe(e.getMessage());
        }

        // if we are here, there's something that went wrong
        return false;
    }
}
