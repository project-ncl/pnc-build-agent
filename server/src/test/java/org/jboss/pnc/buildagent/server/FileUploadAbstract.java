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

import java.io.FileNotFoundException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.jboss.pnc.buildagent.client.BuildAgentHttpClient;
import org.jboss.pnc.buildagent.client.HttpClientConfiguration;
import org.jboss.pnc.buildagent.common.http.HttpClient;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class FileUploadAbstract {

    private static Logger log = LoggerFactory.getLogger(FileUploadAbstract.class);

    public void uploadFile(String host, int port, String contextPath) throws Throwable {
        Path pwd = Paths.get("").toAbsolutePath();
        Path fileUploadPath = Paths.get(pwd.toString(), "/test-upload.txt");

        String fileContent = "The quick brown fox jumps over the lazy dog.";

        HttpClientConfiguration configuration = HttpClientConfiguration.newBuilder()
                .termBaseUrl("http://" + host + ":" + port + contextPath)
                .build();
        BuildAgentHttpClient buildAgentHttpClient = new BuildAgentHttpClient(configuration);
        CompletableFuture<HttpClient.Response> responseFuture = buildAgentHttpClient.uploadFile(
                ByteBuffer.wrap(fileContent.getBytes(StandardCharsets.UTF_8)),
                fileUploadPath);

        HttpClient.Response response = responseFuture.get(10, TimeUnit.SECONDS);
        Assert.assertEquals("Invalid response code.", 200, response.getCode());

        assertFileWasUploaded(fileUploadPath, fileContent);

        fileUploadPath.toFile().delete();
    }

    private void assertFileWasUploaded(Path fileUploadPath, String expectedFileContent) throws FileNotFoundException {
        String actualFileContent = new Scanner(fileUploadPath.toFile()).useDelimiter("\\Z").next();
        log.info("Content written to file: {}", actualFileContent);
        Assert.assertEquals(expectedFileContent, actualFileContent);
    }
}
