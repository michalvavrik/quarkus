package io.quarkus.it.keycloak;

import static io.quarkus.it.keycloak.OidcDPopTest.createWebClient;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.eclipse.microprofile.config.ConfigProvider;
import org.htmlunit.TextPage;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;

import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.filter.log.ResponseLoggingFilter;
import io.restassured.http.ContentType;

@QuarkusTest
class OidcRichAuthorizationRequestsTest {

    @Test
    void testAuthorizationDetails() throws IOException {
        try (final WebClient webClient = createWebClient()) {
            HtmlPage page = webClient.getPage("http://localhost:8081/rar");

            assertEquals("Sign in to quarkus", page.getTitleText());

            HtmlForm loginForm = page.getForms().get(0);

            loginForm.getInputByName("username").setValueAttribute("alice");
            loginForm.getInputByName("password").setValueAttribute("alice");

            TextPage textPage = loginForm.getButtonByName("login").click();

            String jwt = textPage.getContent();
            var jwtJsonObject = OidcUtils.decodeJwtContent(jwt);
            assertEquals("oid4vc-rest-api", jwtJsonObject.getString("azp"));

            // this asserts that the authorization request contained the authorization details request parameter
            String authServerUrl = ConfigProvider.getConfig().getValue("quarkus.oidc.auth-server-url", String.class);
            RestAssured.given()
                    .auth().oauth2(jwt)
                    .contentType(ContentType.JSON)
                    .log().all().filter(new ResponseLoggingFilter()) // FIXME: remove me!
                    .body("""
                            {
                              "credential_configuration_id": "vc-scope-mapping",
                              "credential_definition": {
                                "type": ["VerifiableCredential", "vc-scope-mapping"]
                              },
                              "format": "jwt_vc"
                            }
                            """)
                    .post(authServerUrl + "/protocol/oid4vc/credential")
                    .then().statusCode(200);

            webClient.getCookieManager().clearCookies();
        }
    }

}
