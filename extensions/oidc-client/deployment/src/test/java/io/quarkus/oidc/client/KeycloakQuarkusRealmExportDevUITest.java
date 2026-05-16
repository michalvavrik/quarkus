package io.quarkus.oidc.client;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.databind.JsonNode;

import io.quarkus.devui.tests.DevUIJsonRPCTest;
import io.quarkus.test.QuarkusDevModeTest;

class KeycloakQuarkusRealmExportDevUITest extends DevUIJsonRPCTest {

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource(new StringAsset("quarkus.oidc.enabled=false\n"), "application.properties"));

    KeycloakQuarkusRealmExportDevUITest() {
        super("quarkus-devservices-keycloak");
    }

    @Test
    void exportRealmReturnsValidJson() throws Exception {
        JsonNode result = super.executeJsonRPCMethod("exportRealm");
        assertNotNull(result, "Export should return a result");
        assertTrue(result.has("success"), "Result should have 'success' field");
        assertTrue(result.get("success").asBoolean(), "Export should succeed: " + result);
        String realmJson = result.get("realmJson").asText();
        assertNotNull(realmJson, "Exported JSON should not be null");
        assertTrue(realmJson.contains("quarkus"), "Exported JSON should contain realm name");
        assertTrue(realmJson.contains("alice"), "Exported JSON should contain user alice");
        assertTrue(realmJson.contains("bob"), "Exported JSON should contain user bob");
    }
}
