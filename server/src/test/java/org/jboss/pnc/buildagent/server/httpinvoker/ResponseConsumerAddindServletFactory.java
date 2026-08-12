package org.jboss.pnc.buildagent.server.httpinvoker;

import java.util.function.Consumer;

import io.undertow.servlet.api.InstanceFactory;
import io.undertow.servlet.api.InstanceHandle;
import io.undertow.servlet.util.ImmediateInstanceHandle;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class ResponseConsumerAddindServletFactory implements InstanceFactory<CallbackHandler> {

    private Consumer<String> responseConsumer;

    public ResponseConsumerAddindServletFactory(Consumer<String> responseConsumer) {
        this.responseConsumer = responseConsumer;
    }

    @Override
    public InstanceHandle<CallbackHandler> createInstance() throws InstantiationException {
        return new ImmediateInstanceHandle<>(new CallbackHandler(responseConsumer));
    }
}
