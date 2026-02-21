package io.quarkus.email.authentication.deployment.test;

import static io.quarkus.email.authentication.EmailAuthenticationEvent.FAILURE_KEY;
import static io.quarkus.email.authentication.EmailAuthenticationEvent.PRINCIPAL_NAME_KEY;
import static io.quarkus.email.authentication.EmailAuthenticationEvent.EmailAuthenticationEventType.AUTHENTICATION_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import java.time.temporal.ChronoUnit;
import java.util.Date;

import jakarta.inject.Inject;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.email.authentication.EmailAuthenticationEvent;
import io.quarkus.mailer.MockMailbox;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.spi.runtime.SecurityEvent;
import io.quarkus.test.QuarkusUnitTest;

class EmailAuthenticationDefaultsTest {

    /**
     * These chars correspond to the chars in the email authentication mechanism.
     */
    private static final String ALLOWED_CHARS = "23456789BCDFGHJKMNPQRSTVWXYZ";

    private static final TestEmailAuthenticationHelper HELPER = new TestEmailAuthenticationHelper(
            "/generate-email-authentication-token", "/j_security_check", "Your verification code", "Your verification code is",
            "j_username", "j_token");

    @RegisterExtension
    static final QuarkusUnitTest APP = new QuarkusUnitTest()
            .withApplicationRoot(HELPER.getAppConfig(TestSecurityEventObserver.class));

    @Inject
    MockMailbox mailbox;

    @Inject
    TestSecurityEventObserver eventObserver;

    @BeforeEach
    void reset() {
        HELPER.clear();
        eventObserver.clear();
    }

    @Test
    void testCompleteFlowSuccess() {
        String username = "Vaclav";
        String emailAddress = "test-vaclav@quarkus.io";
        TestTrustedIdentityProvider.addUser(username, emailAddress, "admin");

        // go to secured page and expect redirection to login page where we can submit username
        String targetPath = "/secured/admin";
        HELPER.goTo(targetPath).statusCode(302).header("location", containsString("/login.html"));
        HELPER.assertCookie("quarkus-redirect-location", targetPath);

        // request token and expect redirection to a form where we can submit token
        var expectedTokenCookieExpiration = new Date().toInstant().plus(5, ChronoUnit.MINUTES);
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        var cookie = HELPER.assertCookiePresent("quarkus-credential-request");
        assertThat(cookie.getExpiryDate()).isAfterOrEqualTo(expectedTokenCookieExpiration);
        String token = HELPER.assertEmailAndGetToken(mailbox, emailAddress);
        assertThat(token).hasSize(15);
        for (char c : token.toCharArray()) {
            assertThat(Character.toString(c)).isSubstringOf(ALLOWED_CHARS);
        }

        // login with token and then get session cookie
        HELPER.submitToken(token).statusCode(302).header("location", containsString(targetPath));
        HELPER.assertCookieMissing("quarkus-credential-request");
        HELPER.assertCookieMissing("quarkus-redirect-location");
        HELPER.assertCookiePresent("quarkus-credential");

        // use the session cookie to access a path that requires 'admin' role
        HELPER.goTo(targetPath).statusCode(200).body(is(username + ":" + targetPath));
    }

    @Test
    void testUnknownUsername() {
        assertThat(eventObserver.getEvents()).isEmpty();
        String username = "unknown";
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getEvents()).isNotEmpty());
        var eventAsserter = assertThat(eventObserver.getEvents()).hasSize(1).first();
        eventAsserter.extracting(EmailAuthenticationEvent::getEventType).isEqualTo(AUTHENTICATION_TOKEN);
        eventAsserter.extracting(SecurityEvent::getSecurityIdentity).isNull();
        assertThat(eventAsserter.actual().getEventProperties())
                .isNotEmpty()
                .containsEntry(PRINCIPAL_NAME_KEY, username)
                .containsKey(FAILURE_KEY);
        Object failure = eventAsserter.actual().getEventProperties().get(FAILURE_KEY);
        assertThat(failure).isInstanceOf(AuthenticationFailedException.class);
    }

    @Test
    void testInvalidEmail() {
        assertThat(eventObserver.getEvents()).isEmpty();
        String username = "Martin";
        TestTrustedIdentityProvider.addUser(username, "invalid-email");
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getEvents()).isNotEmpty());
        var eventAsserter = assertThat(eventObserver.getEvents()).hasSize(1).first();
        eventAsserter.extracting(EmailAuthenticationEvent::getEventType).isEqualTo(AUTHENTICATION_TOKEN);
        eventAsserter.extracting(SecurityEvent::getSecurityIdentity).isNull();
        assertThat(eventAsserter.actual().getEventProperties())
                .isNotEmpty()
                .containsEntry(PRINCIPAL_NAME_KEY, username)
                .containsKey(FAILURE_KEY);
        Object failure = eventAsserter.actual().getEventProperties().get(FAILURE_KEY);
        assertThat(failure).isInstanceOf(IllegalArgumentException.class);
        assertThat((IllegalArgumentException) failure).extracting(Throwable::getMessage).asString()
                .contains("'invalid-email' is not valid email address");
    }

    @Test
    void testMissingEmail() {
        assertThat(eventObserver.getEvents()).isEmpty();
        String username = "Martin";
        TestTrustedIdentityProvider.addUser(username, null);
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getEvents()).isNotEmpty());
        var eventAsserter = assertThat(eventObserver.getEvents()).hasSize(1).first();
        eventAsserter.extracting(EmailAuthenticationEvent::getEventType).isEqualTo(AUTHENTICATION_TOKEN);
        eventAsserter.extracting(SecurityEvent::getSecurityIdentity).isNull();
        assertThat(eventAsserter.actual().getEventProperties())
                .isNotEmpty()
                .containsEntry(PRINCIPAL_NAME_KEY, username)
                .containsKey(FAILURE_KEY);
        Object failure = eventAsserter.actual().getEventProperties().get(FAILURE_KEY);
        assertThat(failure).isInstanceOf(IllegalArgumentException.class);
        assertThat((IllegalArgumentException) failure).extracting(Throwable::getMessage).asString()
                .contains("email address or its principal name '" + username + "' must be a valid email address");
    }

    @Test
    void testSwitchUser() {
        // FIXME: write me!
    }
}
