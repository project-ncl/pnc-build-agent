package org.jboss.pnc.buildagent.server.httpinvoker;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;

import org.jboss.pnc.buildagent.server.ReadOnlyChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.termd.core.pty.PtyMaster;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class CommandSession {

    private static final Logger LOGGER = LoggerFactory.getLogger(CommandSession.class);

    private final String sessionId;
    private final Set<ReadOnlyChannel> readOnlyChannels;
    private PtyMaster ptyMaster;

    public CommandSession(Set<ReadOnlyChannel> readOnlyChannels) {
        this.sessionId = UUID.randomUUID().toString();
        this.readOnlyChannels = readOnlyChannels;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setPtyMaster(PtyMaster ptyMaster) {
        this.ptyMaster = ptyMaster;
    }

    public PtyMaster getPtyMaster() {
        return ptyMaster;
    }

    public void close() throws IOException {
        for (ReadOnlyChannel readOnlyChannel : readOnlyChannels) {
            if (readOnlyChannel.isPrimary()) {
                readOnlyChannel.flush();
            }
        }
    }

    public void handleOutput(byte[] buffer) {
        for (ReadOnlyChannel readOnlyChannel : readOnlyChannels) {
            LOGGER.trace(
                    "Writing to chanel {}; stdout: {}",
                    readOnlyChannel,
                    new String(buffer, StandardCharsets.UTF_8));
            readOnlyChannel.writeOutput(buffer);
        }
    }
}
