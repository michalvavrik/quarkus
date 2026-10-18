package io.quarkus.oidc.token.propagation.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.oidc.server.OidcWiremockTestResource;
import io.restassured.RestAssured;

@QuarkusTestResource(OidcWiremockTestResource.class)
class ExchangedTokenCacheSizeTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(FrontendResource.class, ProtectedResource.class, AccessTokenPropagationService.class,
                            MockTokenEndpoint.class)
                    .addAsResource("application-token-exchange.properties", "application.properties"))
            .overrideConfigKey("quarkus.oidc-client.token-cache-max-size", "2");

    @Test
    void testLeastRecentlyUsedExchangedTokenIsEvictedWhenCacheIsFull() {
        String firstToken = tokenIssuedToAlice("first-token");
        String secondToken = tokenIssuedToAlice("second-token");
        String thirdToken = tokenIssuedToAlice("third-token");

        assertExchanged(firstToken);
        assertExchanged(secondToken);
        assertExchanged(thirdToken);
        assertThat(MockTokenEndpoint.exchangeCount(firstToken)).isEqualTo(1);
        assertThat(MockTokenEndpoint.exchangeCount(secondToken)).isEqualTo(1);
        assertThat(MockTokenEndpoint.exchangeCount(thirdToken)).isEqualTo(1);

        assertExchanged(thirdToken);
        assertThat(MockTokenEndpoint.exchangeCount(thirdToken)).isEqualTo(1);

        assertExchanged(firstToken);
        assertThat(MockTokenEndpoint.exchangeCount(firstToken)).isEqualTo(2);
    }

    private static String tokenIssuedToAlice(String subject) {
        return OidcWiremockTestResource.generateJwtToken("alice", Set.of("admin"), subject);
    }

    private static void assertExchanged(String token) {
        RestAssured.given().auth().oauth2(token)
                .when().get("/frontend/token-propagation")
                .then()
                .statusCode(200)
                .body(equalTo("Token issued to alice has been exchanged, new user name: bob"));
    }
}
