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

package org.jboss.pnc.buildagent.server.websockets;

import org.jboss.pnc.buildagent.api.ResponseMode;
import org.jboss.pnc.buildagent.api.Status;
import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.jboss.pnc.buildagent.client.BuildAgentSocketClient;
import org.jboss.pnc.buildagent.common.ObjectWrapper;
import org.jboss.pnc.buildagent.common.Wait;
import org.jboss.pnc.buildagent.server.MockProcess;
import org.jboss.pnc.buildagent.server.TermdServer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static java.lang.Thread.sleep;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class TestWebSocketConnection {

    private static final Logger log = LoggerFactory.getLogger(TestWebSocketConnection.class);

    private static final String HOST = "localhost";
    private static final int PORT = TermdServer.getNextPort();
    private static final String TEST_COMMAND_BASE = "java -cp ./server/target/test-classes/:./target/test-classes/ org.jboss.pnc.buildagent.server.MockProcess";

    private static File logFolder = Paths.get("").toAbsolutePath().toFile();
    private static File logFile = new File(logFolder, "console.log");

    String terminalBaseUrl = "http://" + HOST + ":" + PORT;

    @BeforeClass
    public static void setUP() throws Exception {
        TermdServer.startServer(HOST, PORT, "");
    }

    @AfterClass
    public static void tearDown() {
        TermdServer.stopServer();
        log.debug("Deleting log file {}", logFile);
        logFile.delete();
    }

    @Test
    public void serverShouldBeUpAndRunning() throws Exception {
        String content = readUrl(HOST, PORT, "/");
        Assert.assertTrue("Cannot read response from serverThread.", content.length() > 0);
    }

    @Test
    public void clientShouldBeAbleToRunRemoteCommandAndReceiveBinaryResults() throws Exception {
        clientShouldBeAbleToRunRemoteCommandAndReceiveResults(ResponseMode.BINARY);
    }

    @Test
    public void clientShouldBeAbleToRunRemoteCommandAndReceiveTextResults() throws Exception {
        clientShouldBeAbleToRunRemoteCommandAndReceiveResults(ResponseMode.TEXT);
    }

    public void clientShouldBeAbleToRunRemoteCommandAndReceiveResults(ResponseMode responseMode) throws Exception {
        String context = this.getClass().getName() + ".clientShouldBeAbleToRunRemoteCommandAndReceiveResults" + responseMode;

        List<TaskStatusUpdateEvent> remoteResponseStatuses = new ArrayList<>();
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            remoteResponseStatuses.add(statusUpdateEvent);
        };
        List<String> remoteResponses = new CopyOnWriteArrayList<>();

        Consumer<String> onResponseData = (responseData) -> {
            log.trace("Adding to remote response list [{}].", responseData);
            remoteResponses.add(responseData);
        };
        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(
                terminalBaseUrl,
                Optional.of(onResponseData),
                onStatusUpdate,
                context,
                ResponseMode.BINARY,
                false);
        buildAgentClient.executeCommand(getTestCommand(100, 0));

        assertThatResultWasReceived(remoteResponses, 1000, ChronoUnit.SECONDS);
        assertThatCommandCompletedSuccessfully(remoteResponseStatuses, 1000, ChronoUnit.SECONDS);

        assertThatLogWasWritten(remoteResponseStatuses);

        buildAgentClient.close();
    }

    @Test
    public void shouldExecuteTwoTasksAndWriteToLogs() throws Exception {

        String context = this.getClass().getName() + ".shouldExecuteTwoTasksAndWriteToLogs";

        ObjectWrapper<Boolean> completed = new ObjectWrapper<>(false);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            if (statusUpdateEvent.getNewStatus().equals(Status.COMPLETED) ) {
                log.info("Received status COMPLETED.");
                try {
                    assertTestCommandOutputIsWrittenToLog(statusUpdateEvent.getTaskId());
                } catch (TimeoutException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
                completed.set(true);
            }
        };

        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.empty(), onStatusUpdate, context);

        buildAgentClient.executeCommand(getTestCommand(100, 0));
        Wait.forCondition(() -> completed.get(), 10, ChronoUnit.SECONDS, "Command did not complete in given timeout.");
        completed.set(false);

        buildAgentClient.executeCommand(getTestCommand(100, 0, "2nd-command."));
        Wait.forCondition(() -> completed.get(), 10, ChronoUnit.SECONDS, "Command did not complete in given timeout.");
        completed.set(false);

        buildAgentClient.close();
    }

    @Test
    @Ignore //Readline is not thread safe
    public void shouldEnqueueNewTasksWhenOneIsRunning() throws Exception {

        String context = this.getClass().getName() + ".shouldEnqueueNewTasksWhenFirstIsRunning";

        ObjectWrapper<Integer> completed = new ObjectWrapper<>(0);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            if (statusUpdateEvent.getNewStatus().equals(Status.COMPLETED) ) {
                log.info("Received status COMPLETED.");
                try {
                    assertTestCommandOutputIsWrittenToLog(statusUpdateEvent.getTaskId());
                } catch (TimeoutException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
                completed.set(completed.get() + 1);
            }
        };

        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.empty(), onStatusUpdate, context);

        buildAgentClient.executeCommand(getTestCommand(3, 1));
        buildAgentClient.executeCommand(getTestCommand(3, 0, "2nd-command."));

        Wait.forCondition(() -> completed.get() == 2, 100, ChronoUnit.SECONDS, "Command did not complete in given timeout.");

        buildAgentClient.close();
    }

    @Test
    public void shouldExecuteTwoTasksInSilentMode() throws Exception {

        String context = this.getClass().getName() + ".shouldExecuteTwoTasksInSilentMode";

        ObjectWrapper<Boolean> completed = new ObjectWrapper<>(false);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            if (statusUpdateEvent.getNewStatus().equals(Status.COMPLETED) ) {
                log.info("Received status COMPLETED.");
                try {
                    assertTestCommandOutputIsWrittenToLog(statusUpdateEvent.getTaskId());
                } catch (TimeoutException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
                completed.set(true);
            }
        };

        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.empty(), onStatusUpdate, context, ResponseMode.SILENT, false);

        buildAgentClient.executeCommand(getTestCommand(100, 0));
        Wait.forCondition(() -> completed.get(), 10, ChronoUnit.SECONDS, "Command did not complete in given timeout.");
        completed.set(false);

        buildAgentClient.executeCommand(getTestCommand(100, 0, "2nd-command."));
        Wait.forCondition(() -> completed.get(), 10, ChronoUnit.SECONDS, "Command did not complete in given timeout.");
        completed.set(false);

        buildAgentClient.close();
    }

    @Test
    public void shouldExecuteAndCancelTheExecution() throws Exception {

        String context = this.getClass().getName() + ".shouldExecuteAndCancelTheExecution";

        ObjectWrapper<Boolean> running = new ObjectWrapper<>(false);
        ObjectWrapper<Boolean> interrupted = new ObjectWrapper<>(false);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            log.info("Received status {}.", statusUpdateEvent.getNewStatus());
            if (statusUpdateEvent.getNewStatus().equals(Status.RUNNING) ) {
                running.set(true);
            }
            if (statusUpdateEvent.getNewStatus().equals(Status.FAILED) ) {
                interrupted.set(true);
            }
        };

        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.empty(), onStatusUpdate, context, ResponseMode.SILENT, false);

        buildAgentClient.executeCommand(getTestCommand(3, 1000));
        Wait.forCondition(() -> running.get(), 1, ChronoUnit.SECONDS, "Command did not start in given timeout.");
        sleep(250);
        buildAgentClient.execute('C' - 64);

        Wait.forCondition(() -> interrupted.get(), 1, ChronoUnit.SECONDS, "Command did not get interrupted in given timeout.");

        buildAgentClient.close();
    }

    @Test
    public void clientShouldBeAbleToConnectToRunningProcess() throws Exception {
        String context = this.getClass().getName() + ".clientShouldBeAbleToConnectToRunningProcess";

        ObjectWrapper<Boolean> completed = new ObjectWrapper<>(false);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            if (statusUpdateEvent.getNewStatus().equals(Status.COMPLETED)) {
                completed.set(true);
            }
        };
        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.empty(), onStatusUpdate, context, ResponseMode.BINARY, false);
        buildAgentClient.executeCommand(getTestCommand(100, 20));

        sleep(1000); //wait for async command start
        buildAgentClient.close();

        StringBuilder response = new StringBuilder();
        Consumer<String> onResponse = (message) -> {
            response.append(message);
        };
        BuildAgentSocketClient buildAgentClientReconnected = new BuildAgentSocketClient(terminalBaseUrl, Optional.of(onResponse), onStatusUpdate, context, ResponseMode.BINARY, false);

        Wait.forCondition(() -> completed.get(), 15, ChronoUnit.SECONDS, "Operation did not complete within given timeout.");
        Wait.forCondition(() -> response.toString().contains("I'm done."), 5, ChronoUnit.SECONDS, "Missing or invalid response: " + response.toString());

        buildAgentClientReconnected.close();
    }

    @Test
    public void clientShouldBeAbleToConnectToRunningProcessInDifferentResponseMode() throws Exception {
        String context = this.getClass().getName() + ".clientShouldBeAbleToConnectToRunningProcessInDifferentResponseMode";

        ObjectWrapper<Boolean> completed = new ObjectWrapper<>(false);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            if (statusUpdateEvent.getNewStatus().equals(Status.COMPLETED)) {
                completed.set(true);
            }
        };
        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.empty(), onStatusUpdate, context, ResponseMode.BINARY, false);
        buildAgentClient.executeCommand(getTestCommand(100, 10));

        StringBuilder response = new StringBuilder();
        Consumer<String> onResponse = (message) -> {
            response.append(message);
        };
        BuildAgentSocketClient buildAgentClientReconnected = new BuildAgentSocketClient(
                terminalBaseUrl,
                Optional.of(onResponse),
                (event) -> {},
                context,
                ResponseMode.TEXT,
                true);

        Wait.forCondition(() -> completed.get(), 15, ChronoUnit.SECONDS, "Operation did not complete within given timeout.");
        Wait.forCondition(() -> response.toString().contains("I'm done."), 5, ChronoUnit.SECONDS, "Missing or invalid response: " + response.toString());

        buildAgentClientReconnected.close();
        buildAgentClient.close();
    }

    @Test
    public void textClientShouldReciveOutputWhenCommandStartedInSilentMode() throws Exception {
        String context = this.getClass().getName() + ".clientShouldBeAbleToConnectToRunningProcessInDifferentResponseMode";

        ObjectWrapper<Boolean> completed = new ObjectWrapper<>(false);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            if (statusUpdateEvent.getNewStatus().equals(Status.COMPLETED)) {
                completed.set(true);
            }
        };
        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.empty(), onStatusUpdate, context, ResponseMode.SILENT, false);
        buildAgentClient.executeCommand(getTestCommand(100, 10));

        StringBuilder response = new StringBuilder();
        Consumer<String> onResponse = (message) -> {
            response.append(message);
        };
        BuildAgentSocketClient buildAgentClientReconnected = new BuildAgentSocketClient(
                terminalBaseUrl,
                Optional.of(onResponse),
                (event) -> {},
                context,
                ResponseMode.TEXT,
                true);

        Wait.forCondition(() -> completed.get(), 15, ChronoUnit.SECONDS, "Operation did not complete within given timeout.");
        Wait.forCondition(() -> response.toString().contains("I'm done."), 5, ChronoUnit.SECONDS, "Missing or invalid response: " + response.toString());

        buildAgentClientReconnected.close();
        buildAgentClient.close();
    }

    @Test
    public void clientShouldBeAbleToExecuteCommandWithoutListeningToResponse() throws Exception {
        String context = this.getClass().getName() + ".clientShouldBeAbleToExecuteCommandWithoutListeningToResponse";

        ObjectWrapper<Boolean> completed = new ObjectWrapper<>(false);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            if (statusUpdateEvent.getNewStatus().equals(Status.COMPLETED)) {
                completed.set(true);
            }
        };

        final StringBuilder response = new StringBuilder();
        Consumer<String> onResponse = (message) -> {
            response.append(message);
        };
        final StringBuilder silentResponse = new StringBuilder();
        Consumer<String> onSilentResponse = (message) -> {
            silentResponse.append(message);
        };
        BuildAgentSocketClient buildAgentClientListener = new BuildAgentSocketClient(terminalBaseUrl, Optional.of(onResponse), (event) -> {}, context, ResponseMode.TEXT, true);
        //connect executing client
        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.of(onSilentResponse), onStatusUpdate, context, ResponseMode.SILENT, false);
        buildAgentClient.executeCommand(getTestCommand(100, 0));

        Wait.forCondition(() -> completed.get(), 10, ChronoUnit.SECONDS, "Operation did not complete within given timeout.");
//        wait to make sure async Websocket data has been transferred
        Wait.forCondition(() -> {
            return response.toString().contains("I'm done.");
        }, 3, ChronoUnit.SECONDS, "Missing or invalid response.");

        Assert.assertEquals(0, silentResponse.length());

//        buildAgentClientListener.close();
        buildAgentClient.close();
    }

    @Test
    public void clientShouldBeAbleToConnectAndListenForOutputBeforeTheProcessStart() throws Exception {
        String context = this.getClass().getName() + ".clientShouldBeAbleToConnectToRunningProcessInDifferentResponseMode";

        ObjectWrapper<Boolean> completed = new ObjectWrapper<>(false);
        Consumer<TaskStatusUpdateEvent> onStatusUpdate = (statusUpdateEvent) -> {
            if (statusUpdateEvent.getNewStatus().equals(Status.COMPLETED)) {
                completed.set(true);
            }
        };

        final StringBuilder response = new StringBuilder();
        Consumer<String> onResponse = (message) -> {
            response.append(message);
        };
        BuildAgentSocketClient buildAgentClientListener = new BuildAgentSocketClient(terminalBaseUrl, Optional.of(onResponse), (event) -> {}, context, ResponseMode.TEXT, true);
        //connect executing client
        BuildAgentSocketClient buildAgentClient = new BuildAgentSocketClient(terminalBaseUrl, Optional.empty(), onStatusUpdate, context, ResponseMode.BINARY, false);
        buildAgentClient.executeCommand(getTestCommand(100, 0));

        Wait.forCondition(() -> completed.get(), 10, ChronoUnit.SECONDS, "Operation did not complete within given timeout.");
        //wait to make sure async Websocket data has been transferred
        Wait.forCondition(() -> {
            return response.toString().contains("I'm done.");
        }, 3, ChronoUnit.SECONDS, "Missing or invalid response.");

        buildAgentClientListener.close();
        buildAgentClient.close();
    }

    private void assertThatResultWasReceived(List<String> strings, long timeout, TemporalUnit timeUnit) throws InterruptedException {
        Supplier<Boolean> evaluationSupplier = () -> {
            StringBuilder remoteResponses = new StringBuilder();
            for (String string : strings) {
                remoteResponses.append(string);
            }

            log.trace("Remote responses: {}.", remoteResponses);
            return remoteResponses.toString().contains(MockProcess.DEFAULT_MESSAGE);
        };

        try {
            Wait.forCondition(evaluationSupplier, timeout, timeUnit, "Client did not receive welcome message within given timeout.");
        } catch (TimeoutException e) {
            throw new AssertionError("Response should contain message " + MockProcess.DEFAULT_MESSAGE + ".", e);
        }
    }

    private void assertThatCommandCompletedSuccessfully(List<TaskStatusUpdateEvent> remoteResponseStatuses, long timeout, TemporalUnit timeUnit) throws InterruptedException {
        Supplier<Boolean> checkForResponses = () -> {
            List<TaskStatusUpdateEvent> receivedStatuses = remoteResponseStatuses;
            List<Status> collectedUpdates = receivedStatuses.stream().map(event -> event.getNewStatus()).collect(Collectors.toList());
            return collectedUpdates.contains(Status.RUNNING) && collectedUpdates.contains(Status.COMPLETED);
        };

        try {
            Wait.forCondition(checkForResponses, timeout, timeUnit, "Client was not connected within given timeout.");
        } catch (TimeoutException e) {
            throw new AssertionError("Response should contain status Status.RUNNING and Status.COMPLETED.", e);
        }
    }

    private void assertThatLogWasWritten(List<TaskStatusUpdateEvent> remoteResponseStatuses) throws IOException, TimeoutException, InterruptedException {
        List<TaskStatusUpdateEvent> responses = remoteResponseStatuses;
        Optional<TaskStatusUpdateEvent> firstResponse = responses.stream().findFirst();
        if (!firstResponse.isPresent()) {
            throw new AssertionError("There is no status update event to retrieve task id.");
        }

        TaskStatusUpdateEvent taskStatusUpdateEvent = firstResponse.get();
        String taskId = taskStatusUpdateEvent.getTaskId() + "";

        Supplier<Boolean> completedStatusReceived = () -> {
            for (TaskStatusUpdateEvent event : responses) {
                if (event.getNewStatus().equals(Status.COMPLETED)) {
                    log.debug("Found received completed status for task {}", event.getTaskId());
                    return true;
                }
            }
            return false;
        };
        Wait.forCondition(completedStatusReceived, 10, ChronoUnit.SECONDS, "Client was not connected within given timeout.");

        assertTestCommandOutputIsWrittenToLog(taskId);
    }

    private void assertTestCommandOutputIsWrittenToLog(String taskId) throws TimeoutException, InterruptedException {
        Assert.assertTrue("Missing log file: " + logFile, logFile.exists());

        String fileContent;
        try {
            fileContent = new String(Files.readAllBytes(logFile.toPath()));
        } catch (IOException e) {
            throw new AssertionError("Cannot read log file.", e);
        }
        log.debug("Log file content: [{}].", fileContent);

        Wait.forCondition(() -> fileContent.contains("# Command finished with status: " + Status.COMPLETED.toString()), 3, ChronoUnit.SECONDS, "Missing or invalid completion state of task " + taskId + ".");

        Assert.assertTrue("Missing executed command in log file of task " + taskId + ".", fileContent.contains(getTestCommand(100, 0)));
        Assert.assertTrue("Missing response message in log file of task " + taskId + ".", fileContent.contains("Hello again"));
        Assert.assertTrue("Missing final line in the log file of task " + taskId + ".", fileContent.contains("I'm done."));
    }

    private String readUrl(String host, int port, String path) throws IOException {
        URL url = new URL("http://" + host + ":" + port + path);
        URLConnection connection = url.openConnection();
        connection.connect();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream()));

        String inputLine;
        StringBuilder stringBuilder = new StringBuilder();
        while ((inputLine = bufferedReader.readLine()) != null) {
            stringBuilder.append(inputLine);
        }
        bufferedReader.close();
        return stringBuilder.toString();
    }

    private String getTestCommand(int repeat, int delayMillis) {
        return getTestCommand(repeat, delayMillis, "");
    }

    private String getTestCommand(int repeat, int delayMillis, String customMessage) {
        String command = TEST_COMMAND_BASE + " " + repeat + " " + delayMillis;
        if (customMessage != null && !customMessage.equals("")) {
            command = command + " " + customMessage;
        }
        return command;
    }
}
