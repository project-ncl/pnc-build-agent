package org.jboss.pnc.buildagent.server.logging;

import static org.jboss.pnc.buildagent.server.logging.Mdc.parseMdc;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class MdcTest {

    private static Logger logger = LoggerFactory.getLogger(MdcTest.class);

    @Test
    public void parse() {
        long now = System.currentTimeMillis();
        Optional<Map<String, String>> map = parseMdc("logMDC=processContext:build-239,tmp:false,exp:ts" + now);
        logger.info(map.toString());
        Assert.assertEquals("false", map.get().get("tmp"));
        Assert.assertEquals(Instant.ofEpochMilli(now).toString(), map.get().get("exp"));

        System.out.println();
    }

}
