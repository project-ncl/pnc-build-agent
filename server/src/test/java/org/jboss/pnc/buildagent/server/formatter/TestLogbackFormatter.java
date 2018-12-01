package org.jboss.pnc.buildagent.server.formatter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class TestLogbackFormatter {

    Logger logger = LoggerFactory.getLogger(TestLogbackFormatter.class);

    @Test
    public void shouldReturnJsonFormatted() throws IOException {
        String message = "Major Tom, where is your ship ?";
        LogbackFormatter logbackJsonFormatter = new LogbackFormatter();

        String ctx = "12345";
        MDC.setContextMap(Collections.singletonMap("ctx", ctx));

        String messageJson = logbackJsonFormatter.format(message);

        logger.info(messageJson);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> map = mapper.readValue(messageJson, Map.class);

        Assert.assertEquals(message, map.get("message"));
        Assert.assertEquals("org.jboss.pnc._userlog_.build-log", map.get("logger"));
        Assert.assertEquals(ctx, ((Map)map.get("mdc")).get("ctx"));
    }


}
