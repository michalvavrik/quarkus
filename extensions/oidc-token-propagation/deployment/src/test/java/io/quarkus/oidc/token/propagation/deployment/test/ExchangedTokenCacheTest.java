package io.quarkus.oidc.token.propagation.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;

import java.time.Duration;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.oidc.server.OidcWiremockTestResource;
import io.restassured.RestAssured;

@QuarkusTestResource(OidcWiremockTestResource.class)
class ExchangedTokenCacheTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(FrontendResource.class, ProtectedResource.class, AccessTokenPropagationService.class,
                            MockTokenEndpoint.class)
                    .addAsResource("application-token-exchange.properties", "application.properties"));

    @Test
    void testExchangedTokenIsReusedForSameIncomingToken() {
        String token = tokenIssuedToAlice("same-token");
        MockTokenEndpoint.respondWithTokenIssuedTo(token, "bob");

        assertExchangedUserName(token, "bob");
        assertExchangedUserName(token, "bob");

        assertThat(MockTokenEndpoint.exchangeCount(token)).isEqualTo(1);
    }

    @Test
    void testTokensAreExchangedPerIncomingToken() {
        String firstToken = tokenIssuedToAlice("first-token");
        String secondToken = tokenIssuedToAlice("second-token");
        MockTokenEndpoint.respondWithTokenIssuedTo(firstToken, "bob");
        MockTokenEndpoint.respondWithTokenIssuedTo(secondToken, "carol");

        assertExchangedUserName(firstToken, "bob");
        assertExchangedUserName(secondToken, "carol");
        assertExchangedUserName(firstToken, "bob");
        assertExchangedUserName(secondToken, "carol");

        assertThat(MockTokenEndpoint.exchangeCount(firstToken)).isEqualTo(1);
        assertThat(MockTokenEndpoint.exchangeCount(secondToken)).isEqualTo(1);
    }

    @Test
    void testExpiredExchangedTokenIsExchangedAgain() {
        String token = tokenIssuedToAlice("expiring-token");
        MockTokenEndpoint.respondWithTokenIssuedTo(token, "bob", 2);

        assertExchangedUserName(token, "bob");
        assertExchangedUserName(token, "bob");
        assertThat(MockTokenEndpoint.exchangeCount(token)).isEqualTo(1);

        MockTokenEndpoint.respondWithTokenIssuedTo(token, "carol");
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertExchangedUserName(token, "carol"));
        assertThat(MockTokenEndpoint.exchangeCount(token)).isEqualTo(2);
    }

    @Test
    void testFailedExchangeIsNotCached() {
        String token = tokenIssuedToAlice("failing-token");
        MockTokenEndpoint.respondWithError(token);

        RestAssured.given().auth().oauth2(token)
                .when().get("/frontend/token-propagation")
                .then()
                .statusCode(500);

        MockTokenEndpoint.respondWithTokenIssuedTo(token, "bob");
        assertExchangedUserName(token, "bob");
        assertThat(MockTokenEndpoint.exchangeCount(token)).isEqualTo(2);
    }

    private static String tokenIssuedToAlice(String subject) {
        return OidcWiremockTestResource.generateJwtToken("alice", Set.of("admin"), subject);
    }

    private static void assertExchangedUserName(String token, String userName) {
        RestAssured.given().auth().oauth2(token)
                .when().get("/frontend/token-propagation")
                .then()
                .statusCode(200)
                .body(equalTo("Token issued to alice has been exchanged, new user name: " + userName));
    }
}
