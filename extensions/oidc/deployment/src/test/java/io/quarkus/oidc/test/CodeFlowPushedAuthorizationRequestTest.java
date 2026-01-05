package io.quarkus.oidc.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

public class CodeFlowPushedAuthorizationRequestTest {

    @RegisterExtension
    static final QuarkusUnitTest test = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(ProtectedResource.class, UnprotectedResource.class)
                    .addAsResource(new StringAsset("""
                            quarkus.oidc.client-id=quarkus-app-par-required
                            quarkus.oidc.credentials.secret=secret
                            quarkus.oidc.application-type=web-app
                            quarkus.oidc.authentication.par.enabled=true
                            quarkus.log.category."org.htmlunit".level=ERROR
                            """), "application.properties"));

    @Test
    public void testDefaultTenant() throws IOException {
        try (final WebClient webClient = createWebClient()) {
            HtmlPage page = webClient.getPage("http://localhost:8081/protected");

            assertEquals("Sign in to quarkus", page.getTitleText());

            HtmlForm loginForm = page.getForms().get(0);

            loginForm.getInputByName("username").setValueAttribute("alice");
            loginForm.getInputByName("password").setValueAttribute("alice");

            page = loginForm.getButtonByName("login").click();

            assertEquals("alice", page.getBody().asNormalizedText());

            webClient.getCookieManager().clearCookies();
        }
    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        return webClient;
    }
}
