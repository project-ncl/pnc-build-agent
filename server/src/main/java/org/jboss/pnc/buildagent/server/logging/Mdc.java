package org.jboss.pnc.buildagent.server.logging;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class Mdc {

    private static Logger logger = LoggerFactory.getLogger(Mdc.class);

    private static ObjectMapper mapper = new ObjectMapper();

    public static Optional<Map<String, String>> parseMdc(String logMDC) {
        if (logMDC.startsWith("json:")) {
            String json = logMDC.substring(5);
            try {
                Map<String, String> mdcMap = mapper.readValue(json, Map.class);
                return Optional.of(mdcMap);
            } catch (JsonProcessingException e) {
                logger.warn("Invalid logMdc. Unable to parse json.", e);
                return Optional.empty();
            }
        } else {
            Map<String, String> mdcMap = new HashMap<>();
            String[] keyVals = logMDC.split(",");
            for (String keyVal : keyVals) {
                String[] split = keyVal.split(":");
                if (split.length != 2) {
                    logger.warn(
                            "Invalid logMdc, expected comma-separated list of key value pairs delimited with colon. eg. k1:v1,k2,v2. Found:{}",
                            logMDC);
                    return Optional.empty();
                }
                String key = split[0];
                String value = split[1];
                if (value.startsWith("ts")) {
                    String date = Instant.ofEpochMilli(Long.parseLong(value.substring(2))).toString();
                    mdcMap.put(key, date);
                } else {
                    mdcMap.put(key, value);
                }
            }
            return Optional.of(mdcMap);
        }
    }
}
