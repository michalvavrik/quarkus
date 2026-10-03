package io.quarkus.keycloak.pep.test;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.restassured.RestAssured;

/**
 * Keycloak is not running: the application must start because policy enforcers are created lazily.
 */
public class ProxyWithoutNonProxyHostsStartupTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withEmptyApplication()
            .overrideConfigKey("quarkus.keycloak.policy-enforcer.enabled", "true")
            .overrideConfigKey("quarkus.devservices.enabled", "false")
            .overrideRuntimeConfigKey("quarkus.oidc.auth-server-url", "http://localhost:8180/realms/quarkus")
            .overrideRuntimeConfigKey("quarkus.oidc.client-id", "quarkus-app")
            .overrideRuntimeConfigKey("quarkus.oidc.proxy.proxy-configuration-name", "my-proxy")
            .overrideRuntimeConfigKey("quarkus.proxy.my-proxy.host", "localhost")
            .overrideRuntimeConfigKey("quarkus.proxy.my-proxy.port", "3128");

    @Test
    public void testAppStartsAndPolicyEnforcerIsCreatedOnFirstRequest() {
        // Keycloak is not available, so the lazy PolicyEnforcer creation fails on the first request
        RestAssured.given().get("/anything").then().statusCode(500);
    }
}
