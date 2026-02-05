package org.jboss.pnc.buildagent.server;

import io.jsonwebtoken.Jwts;
import org.junit.Assert;
import org.junit.Test;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class OidcOfflineTokenVerifierTest {

    @Test
    public void testPublicKeyVerification() throws Exception {

        KeyPair kp = generateRSAKeyPair();
        Instant now = Instant.now();
        String authServerUrl = "https://rudolph/realms/test";

        String jwtToken = Jwts.builder()
                .claim("name", "Jane Doe")
                .claim("email", "jane@example.com")
                .subject("jane")
                .id(UUID.randomUUID().toString())
                .issuer(authServerUrl)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                .signWith(kp.getPrivate())
                .compact();

        OidcOfflineTokenVerifier.verify(jwtToken, textPublicKey(kp.getPublic()), authServerUrl);
    }

    @Test
    public void testTokenExpired() throws Exception {

        KeyPair kp = generateRSAKeyPair();
        Instant now = Instant.now();
        String authServerUrl = "https://rudolph/realms/test";

        // this token has already expired
        String jwtToken = Jwts.builder()
                .claim("name", "Jane Doe")
                .claim("email", "jane@example.com")
                .subject("jane")
                .id(UUID.randomUUID().toString())
                .issuer(authServerUrl)
                .issuedAt(Date.from(now.minus(10, ChronoUnit.MINUTES)))
                .expiration(Date.from(now.minus(5, ChronoUnit.MINUTES)))
                .signWith(kp.getPrivate())
                .compact();

        // token expired, so this should fail
        Assert.assertThrows(Exception.class, () -> OidcOfflineTokenVerifier.verify(jwtToken, textPublicKey(kp.getPublic()), authServerUrl));
    }

    @Test
    public void testWrongPublicKey() throws Exception {

        KeyPair kp = generateRSAKeyPair();
        KeyPair kpSecond = generateRSAKeyPair();

        Instant now = Instant.now();
        String authServerUrl = "https://rudolph/realms/test";

        // this token has already expired
        String jwtToken = Jwts.builder()
                .claim("name", "Jane Doe")
                .claim("email", "jane@example.com")
                .subject("jane")
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                .issuer(authServerUrl)
                .signWith(kp.getPrivate())
                .compact();

        // use a completely different public key, this verification should fail
        Assert.assertThrows(Exception.class, () -> OidcOfflineTokenVerifier.verify(jwtToken, textPublicKey(kpSecond.getPublic()), authServerUrl));
    }

    @Test
    public void testWrongIssuer() throws Exception {

        KeyPair kp = generateRSAKeyPair();
        Instant now = Instant.now();
        String issuer = "https://rudolph/test";

        String jwtToken = Jwts.builder()
                .claim("name", "Jane Doe")
                .claim("email", "jane@example.com")
                .subject("jane")
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                .signWith(kp.getPrivate())
                .compact();

        // all good, except with the wrong issuer
        Assert.assertThrows(Exception.class, () -> OidcOfflineTokenVerifier.verify(jwtToken, textPublicKey(kp.getPublic()), "https://booya.com/no"));
    }

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        return kpg.generateKeyPair();
    }

    private String textPublicKey(Key publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}