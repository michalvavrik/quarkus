package io.quarkus.it.keycloak;

import static io.quarkus.it.keycloak.OidcDPopTest.assertInvalidDPoPProofAuthFailureEvent;
import static io.quarkus.it.keycloak.OidcDPopTest.loginAndClick;
import static io.quarkus.it.keycloak.OidcDPopTest.resetDPoPAuthFailureObserver;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.TextPage;
import org.htmlunit.WebClient;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;

@TestProfile(OidcDPopProofAgeTest.EnableProofAge.class)
@QuarkusTest
public class OidcDPopProofAgeTest {

    @Test
    void testDPopProofTooOld() throws Exception {
        try (final WebClient webClient = createWebClient()) {
            resetDPoPAuthFailureObserver();
            TextPage textPage = loginAndClick(webClient, "login-jwt-old-iat");

            assertEquals("401 status from ProtectedResource", textPage.getContent());
            assertInvalidDPoPProofAuthFailureEvent();

            webClient.getCookieManager().clearCookies();
        }
    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        return webClient;
    }

    public static final class EnableProofAge implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("quarkus.oidc.dpop-jwt.dpop.proof-age", "1H");
        }
    }
}
