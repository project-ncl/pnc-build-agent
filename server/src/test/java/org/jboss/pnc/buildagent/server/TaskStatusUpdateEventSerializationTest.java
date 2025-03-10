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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.pnc.buildagent.api.Status;
import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class TaskStatusUpdateEventSerializationTest {

    private static final Logger log = LoggerFactory.getLogger(TaskStatusUpdateEventSerializationTest.class);

    @Test
    public void testTaskStatusUpdateEventSerialization() throws IOException {

        TaskStatusUpdateEvent taskStatusUpdateEvent = new TaskStatusUpdateEvent("123456", Status.NEW, Status.RUNNING, "ctx");

        String taskId = taskStatusUpdateEvent.getTaskId();

        String serialized = taskStatusUpdateEvent.toString();
        log.info("Serialized : {}", serialized);
        ObjectMapper mapper = new ObjectMapper();
        TaskStatusUpdateEvent deserializedTaskStatusUpdateEvent = mapper.readValue(serialized, TaskStatusUpdateEvent.class);

        Assert.assertEquals(taskId, deserializedTaskStatusUpdateEvent.getTaskId());
    }
}
