package org.jboss.pnc.buildagent.server.httpinvoker;

import static io.undertow.servlet.Servlets.defaultContainer;
import static io.undertow.servlet.Servlets.deployment;
import static io.undertow.servlet.Servlets.servlet;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.servlet.Servlet;
import javax.servlet.ServletException;

import org.jboss.pnc.buildagent.server.BootstrapUndertow;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.InstanceFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class HttpServer {
    private Undertow undertow;

    private Map<Class<? extends Servlet>, Optional<InstanceFactory<? extends Servlet>>> servlets = new HashMap<>();

    public void start(int port, String host) throws ServletException {
        DeploymentInfo servletBuilder = deployment()
                .setClassLoader(BootstrapUndertow.class.getClassLoader())
                .setContextPath("/")
                .setDeploymentName("ROOT.war");

        for (Class<? extends Servlet> servletClass : servlets.keySet()) {
            Optional<InstanceFactory<? extends Servlet>> instanceFactory = servlets.get(servletClass);
            if (instanceFactory.isPresent()) {
                servletBuilder.addServlet(
                        servlet(servletClass.getSimpleName(), servletClass, instanceFactory.get())
                                .addMapping(servletClass.getSimpleName()));
            } else {
                servletBuilder.addServlet(
                        servlet(servletClass.getSimpleName(), servletClass)
                                .addMapping(servletClass.getSimpleName()));
            }
        }

        DeploymentManager manager = defaultContainer().addDeployment(servletBuilder);
        manager.deploy();

        HttpHandler servletHandler = null;
        servletHandler = manager.start();

        undertow = Undertow.builder()
                .addHttpListener(port, host)
                .setHandler(servletHandler)
                .build();

        undertow.start();
    }

    public void stop() {
        undertow.stop();
    }

    public void addServlet(
            Class<? extends Servlet> servletClass,
            Optional<InstanceFactory<? extends Servlet>> servletFactory) {
        this.servlets.put(servletClass, servletFactory);
    }
}
