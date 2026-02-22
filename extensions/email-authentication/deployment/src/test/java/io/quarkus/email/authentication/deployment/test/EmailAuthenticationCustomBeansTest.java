package io.quarkus.email.authentication.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.testcontainers.shaded.org.awaitility.Awaitility;

import io.quarkus.email.authentication.EmailAuthenticationTokenSender;
import io.quarkus.email.authentication.EmailAuthenticationTokenStorage;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class EmailAuthenticationCustomBeansTest {

    private static final TestEmailAuthenticationHelper HELPER = new TestEmailAuthenticationHelper(
            "/generate-email-authentication-token", "/j_security_check", "Your verification code", "Your verification code is",
            "j_username", "j_token");

    @RegisterExtension
    static final QuarkusUnitTest APP = new QuarkusUnitTest()
            .withApplicationRoot(HELPER.getAppConfig(CustomSender.class, CustomStorage.class));

    @Inject
    CustomStorage storage;

    @Inject
    CustomSender sender;

    @BeforeEach
    void reset() {
        HELPER.clear();
        sender.principalToToken.clear();
        storage.principalToToken.clear();
    }

    @Test
    void testLoginSuccess() {
        String username = "Vaclav";
        String emailAddress = "test-vaclav@quarkus.io";
        TestTrustedIdentityProvider.addUser(username, emailAddress, "admin");

        // go to secured page and expect redirection to login page where we can submit username
        String targetPath = "/secured/admin";
        HELPER.goTo(targetPath).statusCode(302).header("location", containsString("/login.html"));
        HELPER.assertCookie("quarkus-redirect-location", targetPath);

        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookieMissing("quarkus-credential-request");
        Awaitility.await().until(() -> sender.principalToToken.containsKey(username));
        Awaitility.await().until(() -> storage.principalToToken.containsKey(username));
        assertThat(sender.principalToToken).hasSize(1);
        assertThat(storage.principalToToken).hasSize(1);
        assertThat(sender.principalToToken.get(username)).isEqualTo(storage.principalToToken.get(username));
        String token = storage.principalToToken.get(username);

        // login with token and then get session cookie
        HELPER.submitToken(token).statusCode(302).header("location", containsString(targetPath));
        HELPER.assertCookiePresent("quarkus-credential");

        // use the session cookie to access a path that requires 'admin' role
        HELPER.goTo(targetPath).statusCode(200).body(is(username + ":" + targetPath));
    }

    @Singleton
    static class CustomSender implements EmailAuthenticationTokenSender {

        private final Map<String, String> principalToToken = new ConcurrentHashMap<>();

        @Override
        public Uni<Void> sendToken(char[] token, SecurityIdentity securityIdentity) {
            principalToToken.put(securityIdentity.getPrincipal().getName(), new String(token));
            return Uni.createFrom().voidItem();
        }
    }

    @Singleton
    static class CustomStorage implements EmailAuthenticationTokenStorage {

        private final Map<String, String> principalToToken = new ConcurrentHashMap<>();

        @Override
        public Uni<Void> storeToken(EmailAuthenticationTokenRequest req, String principalName, RoutingContext event) {
            principalToToken.put(principalName, new String(req.token()));
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext) {
            for (var e : principalToToken.entrySet()) {
                String expectedToken = e.getValue();
                if (expectedToken.equals(token)) {
                    return Uni.createFrom().item(e.getKey());
                }
            }
            return Uni.createFrom().nullItem();
        }
    }
}
