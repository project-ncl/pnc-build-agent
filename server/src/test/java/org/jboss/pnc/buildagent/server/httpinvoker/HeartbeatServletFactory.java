package org.jboss.pnc.buildagent.server.httpinvoker;

import java.util.concurrent.atomic.AtomicInteger;

import io.undertow.servlet.api.InstanceFactory;
import io.undertow.servlet.api.InstanceHandle;
import io.undertow.servlet.util.ImmediateInstanceHandle;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class HeartbeatServletFactory implements InstanceFactory<HeartbeatHandler> {

    private AtomicInteger counter;

    public HeartbeatServletFactory(AtomicInteger counter) {
        this.counter = counter;
    }

    @Override
    public InstanceHandle<HeartbeatHandler> createInstance() throws InstantiationException {
        return new ImmediateInstanceHandle<>(new HeartbeatHandler(counter));
    }
}
