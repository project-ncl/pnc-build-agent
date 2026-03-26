package org.jboss.pnc.buildagent.common.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.stream.Collectors;

public class LdapClient {

    private static Logger LOGGER = LoggerFactory.getLogger(LdapClient.class);

    private String auth;

    public LdapClient(String ldapConfigFile) {
        // expecting the content to be: <username>:<password>
        try {
            auth = Files.readAllLines(new File(ldapConfigFile).toPath()).stream().collect(Collectors.joining("\n")).trim();
        } catch (IOException e) {
            LOGGER.error("Cannot read: {}", ldapConfigFile, e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Get the token
     * @return access token
     */
    public String getBasicAuthHeaderValue() {
            return "Basic " + Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
    }
}
