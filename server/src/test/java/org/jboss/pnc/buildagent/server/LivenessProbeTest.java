package org.jboss.pnc.buildagent.server;

import org.jboss.pnc.buildagent.client.BuildAgentClientException;
import org.jboss.pnc.buildagent.client.BuildAgentHttpClient;
import org.junit.Assert;
import org.junit.Test;

import static org.jboss.pnc.buildagent.server.TermdServer.HOST;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class LivenessProbeTest {

    @Test
    public void shouldGetLivenessResponse() throws InterruptedException, BuildAgentClientException {
        int port = TermdServer.getNextPort();
        String terminalBaseUrl = "http://" + HOST + ":" + port;

        BuildAgentHttpClient client = new BuildAgentHttpClient(terminalBaseUrl, null, null);
        Assert.assertFalse(client.isServerAlive());

        TermdServer.startServer(HOST, port, "", true, true);
        Assert.assertTrue(client.isServerAlive());
        TermdServer.stopServer();
    }
}
