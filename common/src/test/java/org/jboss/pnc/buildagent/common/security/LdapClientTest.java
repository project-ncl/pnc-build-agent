package org.jboss.pnc.buildagent.common.security;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class LdapClientTest {

    @Test
    public void testGetBasicAuthHeaderValue() {
        try {
            Path tempFile = Files.createTempFile("processing-", ".txt");
            try {
                List<String> list = new ArrayList<>();
                list.add("username:password\n");
                Files.write(tempFile, list);

                LdapClient ldapClient = new LdapClient(tempFile.toString());
                assertEquals("Basic dXNlcm5hbWU6cGFzc3dvcmQ=", ldapClient.getBasicAuthHeaderValue());

            } finally {
                Files.deleteIfExists(tempFile);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}