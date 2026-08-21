/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.pnc.buildagent.common.security;

import org.junit.Assert;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

public class KeycloakClientConfigurationTest {

    @Test
    public void testConfiguration() throws Exception {
        String text = "{\"url\": \"https://google.com\"," +
                "\"realm\":\"realm\"," +
                "\"clientId\": \"clientId\"," +
                "\"clientSecret\": \"clientSecret\"}";

        ObjectMapper objectMapper = new ObjectMapper();
        KeycloakClientConfiguration configuration = objectMapper.readValue(text, KeycloakClientConfiguration.class);

        Assert.assertEquals("https://google.com", configuration.getUrl());
        Assert.assertEquals("realm", configuration.getRealm());
        Assert.assertEquals("clientId", configuration.getClientId());
        Assert.assertEquals("clientSecret", configuration.getClientSecret());
    }

}