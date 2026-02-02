package io.quarkus.it.keycloak;

import static io.quarkus.it.keycloak.OidcDPopTest.createWebClient;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import org.htmlunit.TextPage;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;

import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
class OidcRichAuthorizationRequestsTest {

    @Test
    void testAuthorizationDetails() throws IOException {
        try (final WebClient webClient = createWebClient()) {
            HtmlPage page = webClient.getPage("http://localhost:8081/single-page-app/login-rar");

            assertEquals("Sign in to quarkus", page.getTitleText());

            HtmlForm loginForm = page.getForms().get(0);

            loginForm.getInputByName("username").setValueAttribute("alice");
            loginForm.getInputByName("password").setValueAttribute("alice");

            TextPage textPage = loginForm.getButtonByName("login").click();

            String jwt = textPage.getContent();
            var jwtJsonObject = OidcUtils.decodeJwtContent(jwt);
            assertEquals("alice", jwtJsonObject.getString("preferred_username"));
            var authorizationDetails = jwtJsonObject.getJsonObject("authorization_details");
            assertNotNull(authorizationDetails);
            // FIXME: test fields!

            webClient.getCookieManager().clearCookies();
        }
    }

}
