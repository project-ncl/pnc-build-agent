package org.jboss.pnc.buildagent.server.logging.formatters.jboss;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import org.jboss.pnc.buildagent.api.logging.LogFormatter;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class JBossFormatterTest {
    private static Logger logger = LoggerFactory.getLogger(JBossFormatterTest.class);

    @Test
    public void shouldReturnJsonFormatted() throws IOException, InstantiationException, InterruptedException {
        String message = "Major Tom, where is your ship ?";
        logger.info("Message: " + message);
        LogFormatter logFormatter = new JBossFormatter();

        String ctx = "12345";
        MDC.setContextMap(Collections.singletonMap("ctx", ctx));

        String messageJson = logFormatter.format(message);

        logger.info(messageJson);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> map = mapper.readValue(messageJson, Map.class);

        Assert.assertEquals(message, map.get("message"));
        Assert.assertEquals("org.jboss.pnc._userlog_.build-log", map.get("loggerName"));
        Assert.assertEquals(ctx, ((Map) map.get("mdc")).get("ctx"));
        Assert.assertEquals("localhost", map.get("hostName"));

        //wait to send out async system logs
        Thread.sleep(1000);
    }

    @Test
    public void shouldTakeCustomProperties() throws IOException, InstantiationException {
        String message = "Major Tom, where is your ship ?";
        logger.info("Message: " + message);

        Properties properties = new Properties();
        properties.load(getClass().getClassLoader().getResourceAsStream("process-logging.properties"));
        LogFormatter logFormatter = new JBossFormatter(properties);

        String ctx = "12345";
        MDC.setContextMap(Collections.singletonMap("ctx", ctx));

        String messageJson = logFormatter.format(message);

        logger.info(messageJson);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> map = mapper.readValue(messageJson, Map.class);

        Assert.assertEquals(message, map.get("message"));
        Assert.assertEquals("org.jboss.pnc._userlog_.build-log", map.get("loggerName"));
        Assert.assertEquals(ctx, ((Map) map.get("mdc")).get("ctx"));
        Assert.assertEquals("localhost", map.get("hostName"));
    }
}