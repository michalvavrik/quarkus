package io.quarkus.email.authentication.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.email.authentication.EmailAuthenticationTokenSender;
import io.quarkus.email.authentication.EmailAuthenticationTokenStorage;
import io.quarkus.security.AuthenticationFailedException;
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
        storage.usedTokens.clear();
        storage.principalToNumOfReq.clear();
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
        String token = getAndAssertToken(username);

        // login with token and then get session cookie
        HELPER.submitToken(token).statusCode(302).header("location", containsString(targetPath));
        HELPER.assertCookiePresent("quarkus-credential");

        // use the session cookie to access a path that requires 'admin' role
        HELPER.goTo(targetPath).statusCode(200).body(is(username + ":" + targetPath));
    }

    @Test
    void testPreventReuse() {
        String username = "Erik";
        TestTrustedIdentityProvider.addUser(username);
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        String token = getAndAssertToken(username);

        // login with token and then get session cookie
        HELPER.submitToken(token).statusCode(302).header("location", containsString("/index.html"));
        HELPER.assertCookiePresent("quarkus-credential");
        HELPER.clear();

        // now try to reuse the token
        HELPER.submitToken(token).statusCode(302).header("location", containsString("/error.html"));
        HELPER.assertCookieMissing("quarkus-credential");
    }

    @Test
    void testPreventTooManyRequests() {
        String username = "Steven";
        TestTrustedIdentityProvider.addUser(username);

        // request number one -> allowed
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        getAndAssertToken(username);

        // request number two -> allowed
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        getAndAssertToken(username);

        // request number three -> allowed
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        getAndAssertToken(username);

        // request number four -> allowed
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        getAndAssertToken(username);

        // request number five -> not allowed, the limit is set to 5
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/error.html"));
    }

    private String getAndAssertToken(String username) {
        Awaitility.await().until(() -> sender.principalToToken.containsKey(username));
        Awaitility.await().until(() -> storage.principalToToken.containsKey(username));
        assertThat(sender.principalToToken).hasSize(1);
        assertThat(storage.principalToToken).hasSize(1);
        assertThat(sender.principalToToken.get(username)).isEqualTo(storage.principalToToken.get(username));
        return storage.principalToToken.get(username);
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
        private final Set<String> usedTokens = ConcurrentHashMap.newKeySet();
        private final Map<String, AtomicInteger> principalToNumOfReq = new ConcurrentHashMap<>();
        private final EmailAuthenticationTokenStorage delegate; // just so that we know it can be used as a delegate

        CustomStorage(DefaultEmailAuthenticationTokenStorage delegate) {
            this.delegate = delegate;
        }

        @Override
        public Uni<Void> storeToken(EmailAuthenticationTokenRequest req, String principal, RoutingContext event) {
            int regNum = principalToNumOfReq.computeIfAbsent(principal, k -> new AtomicInteger()).incrementAndGet();
            if (regNum >= 5) {
                return Uni.createFrom()
                        .failure(new AuthenticationFailedException("Too many requests for principal " + principal));
            }

            principalToToken.put(principal, new String(req.token()));
            return delegate.storeToken(req, principal, event);
        }

        @Override
        public Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext) {
            if (usedTokens.contains(token)) {
                return Uni.createFrom().nullItem();
            }

            usedTokens.add(token);
            for (var e : principalToToken.entrySet()) {
                String expectedToken = e.getValue();
                if (expectedToken.equals(token)) {
                    return Uni.createFrom().item(e.getKey());
                }
            }
            return delegate.findPrincipalNameByToken(token, routingContext);
        }
    }
}
