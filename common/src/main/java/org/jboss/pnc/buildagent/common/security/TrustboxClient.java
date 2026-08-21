package org.jboss.pnc.buildagent.common.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.pnc.api.trustbox.TrustboxTokenRequest;
import org.jboss.pnc.api.trustbox.TrustboxTokenResponse;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TrustboxClient {
    private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static String getAccessToken(
            String trustboxUrl,
            String keycloakAuthServerUrl,
            String clientId,
            String clientSecret) {

        final HttpPost httpPost = new HttpPost(trustboxUrl + "/oidc/token");
        TrustboxTokenRequest request = TrustboxTokenRequest.builder()
                .authServerUrl(keycloakAuthServerUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();

        try {
            final StringEntity entity = new StringEntity(OBJECT_MAPPER.writeValueAsString(request));
            httpPost.setEntity(entity);
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");
        } catch (JsonProcessingException | UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        try (CloseableHttpClient client = HttpClients.createDefault();
                CloseableHttpResponse response = client.execute(httpPost)) {
            TrustboxTokenResponse trustboxTokenResponse = OBJECT_MAPPER
                    .readValue(response.getEntity().getContent(), TrustboxTokenResponse.class);
            return trustboxTokenResponse.getAccessToken();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
