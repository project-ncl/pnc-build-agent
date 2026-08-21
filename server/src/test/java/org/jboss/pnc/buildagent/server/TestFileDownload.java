/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.pnc.buildagent.server;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.jboss.pnc.buildagent.client.BuildAgentClient;
import org.jboss.pnc.buildagent.client.BuildAgentHttpClient;
import org.jboss.pnc.buildagent.client.HttpClientConfiguration;
import org.jboss.pnc.buildagent.common.http.HttpClient;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class TestFileDownload {

    private static final String HOST = "localhost";
    private static final int PORT = TermdServer.getNextPort();

    private static Logger log = LoggerFactory.getLogger(TestFileDownload.class);

    @BeforeClass
    public static void setUP() throws Exception {
        TermdServer.startServer(HOST, PORT, "");
    }

    @AfterClass
    public static void tearDown() {
        TermdServer.stopServer();
    }

    @Test
    public void downloadFile() throws Throwable {
        Path pwd = Paths.get("").toAbsolutePath();
        Path filePath = Paths.get(pwd.toString(), "/test-file.txt");

        String fileContent = "The quick brown fox jumps over the lazy dog.";

        try (PrintWriter out = new PrintWriter(filePath.toFile())) {
            out.write(fileContent);
        }

        HttpClientConfiguration configuration = HttpClientConfiguration.newBuilder()
                .termBaseUrl("http://" + HOST + ":" + PORT)
                .build();
        BuildAgentClient buildAgentHttpClient = new BuildAgentHttpClient(configuration);
        CompletableFuture<HttpClient.Response> responseFuture = buildAgentHttpClient.downloadFile(filePath);

        HttpClient.Response response = responseFuture.get(10, TimeUnit.SECONDS);
        Assert.assertEquals("Invalid response code.", 200, response.getCode());
        log.info("Received file content: {}", response.getStringResult().getString());
        Assert.assertEquals(fileContent, response.getStringResult().getString());

        filePath.toFile().delete();
    }

}
