package io.quarkus.email.authentication.deployment.test;

import static io.quarkus.email.authentication.EmailAuthenticationEvent.AUTHENTICATION_TOKEN_KEY;
import static io.quarkus.email.authentication.EmailAuthenticationEvent.FAILURE_KEY;
import static io.quarkus.email.authentication.EmailAuthenticationEvent.PRINCIPAL_NAME_KEY;
import static io.quarkus.email.authentication.EmailAuthenticationEvent.EmailAuthenticationEventType.AUTHENTICATION_TOKEN;
import static io.quarkus.email.authentication.EmailAuthenticationEvent.EmailAuthenticationEventType.EMAIL_LOGIN;
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
import io.quarkus.security.spi.runtime.AbstractSecurityEvent;
import io.quarkus.security.spi.runtime.AuthenticationFailureEvent;
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
        mailbox.clear();
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
        assertThat(eventObserver.getEmailAuthenticationEvents()).isEmpty();
        String username = "unknown";
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getEmailAuthenticationEvents()).isNotEmpty());
        var eventAsserter = assertThat(eventObserver.getEmailAuthenticationEvents()).hasSize(1).first();
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
        assertThat(eventObserver.getEmailAuthenticationEvents()).isEmpty();
        String username = "Martin";
        TestTrustedIdentityProvider.addUser(username, "invalid-email");
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getEmailAuthenticationEvents()).isNotEmpty());
        var eventAsserter = assertThat(eventObserver.getEmailAuthenticationEvents()).hasSize(1).first();
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
        assertThat(eventObserver.getEmailAuthenticationEvents()).isEmpty();
        String username = "Martin";
        TestTrustedIdentityProvider.addUser(username, null);
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getEmailAuthenticationEvents()).isNotEmpty());
        var eventAsserter = assertThat(eventObserver.getEmailAuthenticationEvents()).hasSize(1).first();
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
        String principalName = "test-vaclav@quarkus.io";
        String principalName2 = "test-martin@quarkus.io";
        TestTrustedIdentityProvider.addUser(principalName).addUser(principalName2, null, "admin");

        // request token and expect redirection to a form where we can submit token
        HELPER.requestTokenFor(principalName).statusCode(302).header("location", containsString("/token.html"));
        String token = HELPER.assertEmailAndGetToken(mailbox, principalName);
        assertThat(token).hasSize(15);

        // we should receive security event with the token
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getEmailAuthenticationEvents()).isNotEmpty());
        var eventAsserter = assertThat(eventObserver.getEmailAuthenticationEvents()).hasSize(1).first();
        eventAsserter.extracting(EmailAuthenticationEvent::getEventType).isEqualTo(AUTHENTICATION_TOKEN);
        eventAsserter.extracting(EmailAuthenticationEvent::getSecurityIdentity).isNotNull();
        var eventPropertiesAsserter = assertThat(eventAsserter.actual().getEventProperties()).isNotEmpty();
        eventPropertiesAsserter.containsKey(AUTHENTICATION_TOKEN_KEY);
        eventPropertiesAsserter.doesNotContainKey(FAILURE_KEY);
        eventObserver.clear();

        // login with token and then get session cookie
        HELPER.submitToken(token).statusCode(302).header("location", containsString("/index.html"));
        HELPER.assertCookiePresent("quarkus-credential");

        // we should receive the login event
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getEmailAuthenticationEvents()).isNotEmpty());
        eventAsserter = assertThat(eventObserver.getEmailAuthenticationEvents()).hasSize(1).first();
        eventAsserter.extracting(EmailAuthenticationEvent::getEventType).isEqualTo(EMAIL_LOGIN);
        eventAsserter.extracting(EmailAuthenticationEvent::getSecurityIdentity).isNotNull();
        eventPropertiesAsserter = assertThat(eventAsserter.actual().getEventProperties()).isNotEmpty();
        eventPropertiesAsserter.containsKey(AUTHENTICATION_TOKEN_KEY);
        eventPropertiesAsserter.doesNotContainKey(FAILURE_KEY);
        eventObserver.clear();

        // use the session cookie to access a path that requires 'admin' role
        HELPER.goTo("/secured/any").statusCode(200).body(is(principalName + ":/secured/any"));

        // this user is missing the admin role
        HELPER.goTo("/secured/admin").statusCode(403);

        // == SWITCH USER

        // request token and expect redirection to a form where we can submit token
        HELPER.requestTokenFor(principalName2).statusCode(302).header("location", containsString("/token.html"));
        String newToken = HELPER.assertEmailAndGetToken(mailbox, principalName2);
        assertThat(newToken).hasSize(15).asString().isNotEqualToIgnoringCase(token);

        // login with token and then get session cookie
        HELPER.submitToken(newToken).statusCode(302).header("location", containsString("/index.html"));
        HELPER.assertCookiePresent("quarkus-credential");

        // use the session cookie to access a path that requires 'admin' role
        HELPER.goTo("/secured/any").statusCode(200).body(is(principalName2 + ":/secured/any"));

        // this user has the admin role
        HELPER.goTo("/secured/admin").statusCode(200).body(is(principalName2 + ":/secured/admin"));
    }

    @Test
    void testInvalidTokenWithoutRequestCookie() {
        testInvalidToken();
    }

    @Test
    void testInvalidTokenWithRequestCookie() {
        TestTrustedIdentityProvider.addUser("Albus", "albus@quarkus.io");
        HELPER.requestTokenFor("Albus").statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");

        testInvalidToken();
    }

    @Test
    void testValidTokenWithoutRequestCookie() {
        String token = getTokenAndDeleteRequestCookie();

        HELPER.submitToken(token).statusCode(302).header("location", containsString("/error.html"));
    }

    @Test
    void testValidTokenWithInvalidRequestCookie() {
        String token = getTokenAndDeleteRequestCookie();

        HELPER.addCookie("quarkus-credential-request", "abcdefg");

        HELPER.submitToken(token).statusCode(302).header("location", containsString("/error.html"));
    }

    @Test
    void testValidTokenWithMismatchedValidRequestCookie() {
        String tokenA = getTokenAndDeleteRequestCookie("A");

        TestTrustedIdentityProvider.addUser("B", "B@quarkus.io");
        getToken("B", "B@quarkus.io");
        HELPER.assertCookiePresent("quarkus-credential-request");

        HELPER.submitToken(tokenA).statusCode(302).header("location", containsString("/error.html"));
    }

    private String getTokenAndDeleteRequestCookie(String... postfixes) {
        String email = "albus@quarkus.io" + String.join("", postfixes);
        String username = "Albus";
        TestTrustedIdentityProvider.addUser(username, email);
        String token = getToken(username, email);

        // delete cookies
        HELPER.clear();
        TestTrustedIdentityProvider.addUser(username, email);
        HELPER.assertCookieMissing("quarkus-credential-request");

        return token;
    }

    private String getToken(String username, String email) {
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");
        String token = HELPER.assertEmailAndGetToken(mailbox, email);
        assertThat(token).hasSize(15);
        return token;
    }

    private void testInvalidToken() {
        HELPER.submitToken("wrong-wrong").statusCode(302).header("location", containsString("/error.html"));
        Awaitility.await().untilAsserted(() -> assertThat(eventObserver.getAuthFailedEvents()).isNotEmpty());
        var authFailedEvents = eventObserver.getAuthFailedEvents();
        var eventAsserter = assertThat(authFailedEvents).hasSize(1).first();
        eventAsserter.extracting(AbstractSecurityEvent::getSecurityIdentity).isNull();
        eventAsserter.extracting(AuthenticationFailureEvent::getAuthenticationFailure).isNotNull()
                .isInstanceOf(AuthenticationFailedException.class);
        AuthenticationFailedException exception = (AuthenticationFailedException) eventAsserter.actual()
                .getAuthenticationFailure();
        assertThat(exception).extracting(Throwable::getMessage).asString()
                .contains("Cannot authentication with unknown or invalid token: " + "wrong-wrong");
    }

}
