package io.quarkus.email.authentication.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import java.time.temporal.ChronoUnit;
import java.util.Date;

import jakarta.inject.Inject;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.mailer.MockMailbox;
import io.quarkus.test.QuarkusUnitTest;

class EmailAuthenticationConfigPropertiesTest {

    private static final TestEmailAuthenticationHelper HELPER = new TestEmailAuthenticationHelper(
            "/gen-token", "/post-location", "code is here!", "token is ",
            "username-param", "token-param");

    @RegisterExtension
    static final QuarkusUnitTest APP = new QuarkusUnitTest()
            .withApplicationRoot(HELPER.getNamedMailAppConfig("named-1", TestSecurityEventObserver.class))
            .overrideConfigKey("quarkus.email-authentication.mailer-name", "named-1")
            .withRuntimeConfiguration("""
                    quarkus.email-authentication.email-text=token is %s
                    quarkus.email-authentication.email-subject=code is here!
                    quarkus.email-authentication.token-cookie=token-req
                    quarkus.email-authentication.token-expires-in=3s
                    quarkus.email-authentication.token-generation-location=gen-token
                    quarkus.email-authentication.token-length=7
                    quarkus.email-authentication.token-parameter=token-param
                    quarkus.email-authentication.token-page=token-form.html
                    quarkus.email-authentication.priority=2001
                    quarkus.email-authentication.post-location=post-location
                    quarkus.email-authentication.cookie-same-site=lax
                    quarkus.email-authentication.http-only-cookie=false
                    quarkus.email-authentication.cookie-domain=localhost
                    quarkus.email-authentication.cookie-path=secured
                    quarkus.email-authentication.session-cookie=quarkus-session-cookie
                    quarkus.email-authentication.location-cookie=quarkus-redir-link
                    quarkus.email-authentication.landing-page=secured
                    quarkus.email-authentication.error-page=err.html
                    quarkus.email-authentication.username-parameter=username-param
                    quarkus.email-authentication.login-page=log-me-in.html
                    """);

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
        HELPER.goTo(targetPath).statusCode(302).header("location", containsString("/log-me-in.html"));
        HELPER.assertCookie("quarkus-redir-link", targetPath);

        // request token and expect redirection to a form where we can submit token
        var expectedTokenCookieExpiration = new Date().toInstant().plus(3, ChronoUnit.SECONDS);
        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token-form.html"));
        var cookie = HELPER.assertCookiePresent("token-req");
        assertThat(cookie.getExpiryDate()).isAfterOrEqualTo(expectedTokenCookieExpiration);
        String token = HELPER.assertEmailAndGetToken(mailbox, emailAddress);
        assertThat(token).hasSize(7);
        for (char c : token.toCharArray()) { // we only allow certain characters to be in the generated token
            assertThat(Character.toString(c)).isSubstringOf("23456789BCDFGHJKMNPQRSTVWXYZ");
        }

        // login with token and then get session cookie
        HELPER.submitToken(token).statusCode(302).header("location", containsString(targetPath));
        HELPER.assertCookieMissing("token-req");
        HELPER.assertCookieMissing("quarkus-redir-link");
        HELPER.assertCookiePresent("quarkus-session-cookie");

        // use the session cookie to access a path that requires 'admin' role
        HELPER.goTo(targetPath).statusCode(200).body(is(username + ":" + targetPath));
    }

}
