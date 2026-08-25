package org.jboss.pnc.buildagent.common.http;

import java.util.List;

import org.jboss.pnc.api.dto.Request;

public interface HeartbeatHttpHeaderProvider {
    List<Request.Header> getHeaders();
}
