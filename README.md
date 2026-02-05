Building and Packaging
======================


To compile project run

    mvn clean install

To pack all in one executable jar run

    mvn assembly:single

Running
=======
java -jar server/target/server-0.4-SNAPSHOT-jar-with-dependencies.jar -h

Example using Kafka destination: -kp enables Kafka, -pl defines is as the destination where the compelte log must be written.

    java -jar server/target/server-0.4-SNAPSHOT-jar-with-dependencies.jar -kp $PWD/kafka.properties -pl KAFKA

Authentication of Build Agent endpoints
=======================================
build-agent can be configured to require an OIDC token for some endpoints. This is done by providing the `authHeaderConfig` option with the appropriate file.

The `authHeaderConfig` is used to validate the token for OIDC/OAuth/OpenID using offline techniques only using the public key (obtained from {auth url}/auth/realms/{realm}) and the issuer url only. This is useful when we run build-agent inside a firewall that limits outgoing connections to other servers. It is also used to verify Basic authentication using LDAP. The format of the file to provide is:
```json
{
  "realm-public-key": "public-key",
  "auth-server-url": "{auth-url}/auth/realms/realm",
  "ldap-host": "ldap.test.com",
  "ldap-port": 636,
  "ldap-search-base": "ou=company.com"
}
```

Keycloak Client
===============
The build-agent sends a callback on completion to the original caller. The callback needs to be authenticated to be
accepted by the original caller. To obtain the proper Authorization access token for the callback, use the CLI option:
```
-DkeycloakClientConfigFile=<filename>
```

The filename should have the following content:
```json
{
    "url": "https://keycloak-url",
    "realm": "realm",
    "clientId": "client-id",
    "clientSecret": "client-secret",
    "trustboxUrl": "http://url",
    "useTrustbox": false
}
```
(The trustbox stuff is explained below)

Only client credentials flow (service account authentication) is supported at this moment.

## Keycloak jump box (Trustbox)

Since the build-agent is typically run inside a hermetic environment where outgoing connections are blocked by a
firewall unless in an allow-list [1], this causes problems when talking to the Keycloak server. (See
the `keycloakConfigurationFile` for validation of received of OIDC access token without talking to the Keycloak server).

When the build-agent wants to get a new OIDC access token to talk to other services, it will have trouble reaching out
to the Keycloak server. Instead, we can use a "jump box" for:

```
build-agent --> jump box --> keycloak server
```

The jump box project can be found [here](https://github.com/project-ncl/trustbox).

The jump box will always have the same IP address[2] (as opposed to the Keycloak server) that we can add to the allow-list.
It acts as a proxy to the Keycloak server, and nothing more. The implementation can be found [here](https://github.com/thescouser89/trustbox).

The request to the server is:
```
# POST to endpoint jumpbox/oidc/token with content
{
    "authServerUrl": "https://auth.server/auth/realms/realm",
    "clientId": "client-id",
    "clientSecret": "client-secret"
}
```
with response:
```
{
    "accessToken": "blabla"
}
```

While it's scary that we are sending secrets to the jump box, the latter does not log the values and stores the data. It
really just acts as a proxy.

It is activated by using the keycloakClientConfigFile and setting useTrustbox = true with the trustbox url pointing to a real server.

[1]: There are multiple IP addresses that map to our Keycloak server, and there are no guarantees that the IP addresses
will always stay the same. Therefore we need to find another solution

[2]: we can guarantee this by using the Kubernetes service object which always has the same IP address
