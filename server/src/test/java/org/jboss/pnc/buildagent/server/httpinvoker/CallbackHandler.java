package org.jboss.pnc.buildagent.server.httpinvoker;

import java.io.IOException;
import java.util.function.Consumer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class CallbackHandler extends HttpServlet {

    private Consumer<String> responseConsumer;

    public CallbackHandler(Consumer<String> responseConsumer) {
        this.responseConsumer = responseConsumer;
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse resp) throws ServletException, IOException {
        StringBuilder stringBuilder = new StringBuilder();
        request.getReader().lines().forEach(line -> stringBuilder.append(line));
        responseConsumer.accept(stringBuilder.toString());
    }
}
