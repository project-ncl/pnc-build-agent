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

package org.jboss.pnc.buildagent.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@JsonDeserialize(builder = TaskStatusUpdateEvent.Builder.class)
public class TaskStatusUpdateEvent implements Serializable {

  private static final Logger log = LoggerFactory.getLogger(TaskStatusUpdateEvent.class);

  private final String taskId;
  private final Status newStatus;
  private final String outputChecksum;
  private final String message;

  @Deprecated
  private final Status oldStatus;
  @Deprecated
  private final String context;

  @Deprecated
  public TaskStatusUpdateEvent(String taskId, Status oldStatus, Status newStatus, String context, String outputChecksum) {
    this.taskId = taskId;
    this.oldStatus = oldStatus;
    this.newStatus = newStatus;
    this.context = context;
    this.outputChecksum = outputChecksum;
    this.message = "";
  }

  @Deprecated
  public TaskStatusUpdateEvent(String taskId, Status oldStatus, Status newStatus, String context) {
    this.taskId = taskId;
    this.oldStatus = oldStatus;
    this.newStatus = newStatus;
    this.context = context;
    this.outputChecksum = "";
    this.message = "";
  }

  private TaskStatusUpdateEvent(Builder builder) {
    taskId = builder.taskId;
    newStatus = builder.newStatus;
    outputChecksum = builder.outputChecksum;
    message = builder.message;
    oldStatus = builder.oldStatus;
    context = builder.context;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static Builder newBuilder(TaskStatusUpdateEvent copy) {
    Builder builder = new Builder();
    builder.taskId = copy.getTaskId();
    builder.newStatus = copy.getNewStatus();
    builder.outputChecksum = copy.getOutputChecksum();
    builder.message = copy.getMessage();
    builder.oldStatus = copy.getOldStatus();
    builder.context = copy.getContext();
    return builder;
  }

  public String getTaskId() {
    return taskId;
  }

  @Deprecated
  public Status getOldStatus() {
    return oldStatus;
  }

  public Status getNewStatus() {
    return newStatus;
  }

  @Deprecated
  public String getContext() {
    return context;
  }

  public String getOutputChecksum() {
    return outputChecksum;
  }

  public String getMessage() {
    return message;
  }

  public String toString() {
    ObjectMapper mapper = new ObjectMapper();
    try {
      return mapper.writeValueAsString(this);
    } catch (JsonProcessingException e) {
      log.error("Cannot serialize object.", e);
    }
    return null;
  }

  @JsonPOJOBuilder(withPrefix = "")
  public static final class Builder {

    private String taskId;

    private Status newStatus;

    private String outputChecksum;

    private String message;

    private Status oldStatus;

    private String context;

    private Builder() {
    }

    public Builder taskId(String taskId) {
      this.taskId = taskId;
      return this;
    }

    public Builder newStatus(Status newStatus) {
      this.newStatus = newStatus;
      return this;
    }

    public Builder outputChecksum(String outputChecksum) {
      this.outputChecksum = outputChecksum;
      return this;
    }

    public Builder message(String message) {
      this.message = message;
      return this;
    }

    @Deprecated
    public Builder oldStatus(Status oldStatus) {
      this.oldStatus = oldStatus;
      return this;
    }

    @Deprecated
    public Builder context(String context) {
      this.context = context;
      return this;
    }

    public TaskStatusUpdateEvent build() {
      return new TaskStatusUpdateEvent(this);
    }
  }

}
