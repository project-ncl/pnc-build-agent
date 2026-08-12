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

import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.jboss.pnc.buildagent.api.Status;
import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.jboss.pnc.buildagent.client.BuildAgentClient;
import org.jboss.pnc.buildagent.client.BuildAgentHttpClient;
import org.jboss.pnc.buildagent.client.BuildAgentSocketClient;
import org.jboss.pnc.buildagent.client.HttpClientConfiguration;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class TestGetRunningProcesses {

    private static final String HOST = "localhost";
    private static final int PORT = TermdServer.getNextPort();

    private static Logger log = LoggerFactory.getLogger(TestGetRunningProcesses.class);

    private static final String TEST_COMMAND = "java -cp ./target/test-classes/:./server/target/test-classes/ org.jboss.pnc.buildagent.server.MockProcess 1 500";

    @BeforeClass
    public static void setUP() throws Exception {
        TermdServer.startServer(HOST, PORT, "");
    }

    @AfterClass
    public static void tearDown() {
        TermdServer.stopServer();
    }

    @Test
    public void getRunningProcesses() throws Throwable {
        String terminalUrl = "http://" + HOST + ":" + PORT;

        String context = this.getClass().getName() + ".getRunningProcesses";

        BlockingQueue<Status> runningUpdate = new ArrayBlockingQueue<>(1);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            Status newStatus = statusUpdateEvent.getNewStatus();
            if (newStatus.equals(Status.RUNNING)) {
                runningUpdate.add(newStatus);
            }
        };

        HttpClientConfiguration configuration = HttpClientConfiguration.newBuilder()
                .termBaseUrl(terminalUrl)
                .build();
        //http client does not create active terminal on connect
        BuildAgentClient buildAgentHttpClient = new BuildAgentHttpClient(configuration);
        Assert.assertEquals(0, buildAgentHttpClient.getRunningProcesses().get(3, TimeUnit.SECONDS).size());
        BuildAgentClient buildAgentClient = new BuildAgentSocketClient(
                terminalUrl,
                Optional.empty(),
                onStatusUpdate,
                context);
        Assert.assertEquals(1, buildAgentHttpClient.getRunningProcesses().get(3, TimeUnit.SECONDS).size());

        buildAgentClient.execute(TEST_COMMAND);
        runningUpdate.poll(3, TimeUnit.SECONDS);
        Assert.assertEquals(1, buildAgentHttpClient.getRunningProcesses().get(3, TimeUnit.SECONDS).size());

        buildAgentClient.close();
    }
}
