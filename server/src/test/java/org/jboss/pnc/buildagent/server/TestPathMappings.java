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

import org.jboss.pnc.buildagent.common.BuildAgentException;
import org.jboss.pnc.buildagent.common.RandomUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.jboss.pnc.buildagent.common.http.HttpClient.DEFAULT_HTTP_READ;
import static org.jboss.pnc.buildagent.common.http.HttpClient.DEFAULT_HTTP_WRITE;


/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class TestPathMappings {

    private static final String HOST = "localhost";

    private static Logger log = LoggerFactory.getLogger(TestPathMappings.class);

    @Test
    public void serverShouldListenOnRoot() throws BuildAgentException, InterruptedException, IOException {
        Map<String, String> mdcMap = new HashMap<>();
        mdcMap.put("ctx", RandomUtils.randString(8));
        Options options = new Options(HOST, 0, "", true, false, 3, 100, null, "", "", DEFAULT_HTTP_READ, DEFAULT_HTTP_WRITE);

        BuildAgentServer buildAgent = new BuildAgentServer(Optional.empty(), Optional.empty(), new IoLoggerName[0], options, mdcMap);

        HttpURLConnection connection200 = connectToUrl(buildAgent.getPort(), "");
        Assert.assertEquals("Unexpected http response code.", 200, connection200.getResponseCode());

        HttpURLConnection connection404 = connectToUrl(buildAgent.getPort(), "wrong");
        Assert.assertEquals("Unexpected http response code.", 404, connection404.getResponseCode());

        buildAgent.stop();
    }

    @Test
    public void serverShouldListenOnPath() throws InterruptedException, IOException, BuildAgentException {
        Map<String, String> mdcMap = new HashMap<>();
        mdcMap.put("ctx", RandomUtils.randString(8));
        String contextPath = "ctx-path";
        Options options = new Options(HOST, 0, "/" + contextPath, true, false,3, 100, null, "", "", DEFAULT_HTTP_READ, DEFAULT_HTTP_WRITE);
        BuildAgentServer buildAgent = new BuildAgentServer(Optional.empty(), Optional.empty(), new IoLoggerName[0], options, mdcMap);

        HttpURLConnection connection200 = connectToUrl(buildAgent.getPort(), contextPath);
        Assert.assertEquals("Unexpected http response code.", 200, connection200.getResponseCode());

        HttpURLConnection connection404 = connectToUrl(buildAgent.getPort(), "");
        Assert.assertEquals("Unexpected http response code.", 404, connection404.getResponseCode());

        HttpURLConnection connection404WithPath = connectToUrl(buildAgent.getPort(), contextPath + "/wrong");
        Assert.assertEquals("Unexpected http response code.", 404, connection404WithPath.getResponseCode());

        buildAgent.stop();
    }


    private HttpURLConnection connectToUrl(int port, String path) throws IOException {
        URL url = new URL("http://" + HOST + ":" + port + "/" + path);
        log.debug("Connecting to {}", url);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(500);
        connection.setRequestMethod("GET");
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.connect();
        return connection;
    }

}