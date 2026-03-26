package org.jboss.pnc.buildagent.server;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class OidcOfflineTokenVerifier {

    /**
     * Verify that the JWT token is valid, given the public key and the auth-server-url
     * If the JWT token has expired, the verification will fail.
     * If the verification fails, an exception is thrown.
     *
     * @param jwtString     token to verify
     * @param publicKey     public key of auth issuer: from {auth url}/auth/realms/{realm}
     * @param authServerUrl auth-server-url in format: {auth url/auth/realms/realm} for keycloak. Used to verify source of token matches the one we want
     * @throws Exception if verification fails
     */
    public static void verify(String jwtString, String publicKey, String authServerUrl) throws Exception {

        // if the public key doesn't match (token is compromised) then this throws an exception.
        // if the token is expired, this also throws an exception
        Jws<Claims> jws = parseJwt(jwtString, publicKey);

        String tokenIssuer = jws.getPayload().getIssuer();

        if (!tokenIssuer.equals(authServerUrl)) {
            throw new RuntimeException("Token issuer " + tokenIssuer + " doesn't match with the configured issuer: " + authServerUrl);
        }
    }

    private static Jws<Claims> parseJwt(String jwtString, String publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {

        PublicKey publicKeyObj = getPublicKeyObject(publicKey);

        return Jwts.parser()
                .verifyWith(publicKeyObj)
                .build()
                .parseSignedClaims(jwtString);
    }

    private static PublicKey getPublicKeyObject(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String rsaPublicKey = "-----BEGIN PUBLIC KEY-----" + publicKey + "-----END PUBLIC KEY-----";
        rsaPublicKey = rsaPublicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        rsaPublicKey = rsaPublicKey.replace("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }
}
