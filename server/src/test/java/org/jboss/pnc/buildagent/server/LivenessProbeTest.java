package org.jboss.pnc.buildagent.server;

import static org.jboss.pnc.buildagent.server.TermdServer.HOST;

import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.client.BuildAgentClientException;
import org.jboss.pnc.buildagent.client.BuildAgentHttpClient;
import org.jboss.pnc.buildagent.client.HttpClientConfiguration;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class LivenessProbeTest {

    @Test
    public void shouldGetLivenessResponse() throws InterruptedException, BuildAgentClientException {
        int port = TermdServer.getNextPort();
        String terminalBaseUrl = "http://" + HOST + ":" + port;

        HttpClientConfiguration configuration = HttpClientConfiguration.newBuilder()
                .termBaseUrl(terminalBaseUrl)
                .callback(new Request(Request.Method.GET, null))
                .build();
        BuildAgentHttpClient client = new BuildAgentHttpClient(configuration);
        Assert.assertFalse(client.isServerAlive());

        TermdServer.startServer(HOST, port, "", true, true);
        Assert.assertTrue(client.isServerAlive());
        TermdServer.stopServer();
        Assert.assertFalse(client.isServerAlive());
    }
}
