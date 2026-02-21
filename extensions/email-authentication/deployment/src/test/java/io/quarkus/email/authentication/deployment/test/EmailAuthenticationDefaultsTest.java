package io.quarkus.email.authentication.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import jakarta.inject.Inject;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.mailer.MockMailbox;
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
    static final QuarkusUnitTest APP = new QuarkusUnitTest().withApplicationRoot(HELPER.getAppConfig());

    @Inject
    MockMailbox mailbox;

    @BeforeEach
    void reset() {
        HELPER.clear();
    }

    @Test
    void testCompleteFlowSuccess() {
        String username = "Vaclav";
        String emailAddress = "test-vaclav@quarkus.io";
        TestTrustedIdentityProvider.reset().addUser(username, emailAddress, "admin");

        String targetPath = "/secured/admin";
        HELPER.goTo(targetPath).statusCode(302).header("location", containsString("/login.html"));
        HELPER.assertCookie("quarkus-redirect-location", targetPath);

        HELPER.requestTokenFor(username).statusCode(302).header("location", containsString("/token.html"));
        HELPER.assertCookiePresent("quarkus-credential-request");
        String token = HELPER.assertEmailAndGetToken(mailbox, emailAddress);
        assertThat(token).hasSize(15);
        for (char c : token.toCharArray()) {
            assertThat(Character.toString(c)).isSubstringOf(ALLOWED_CHARS);
        }

        HELPER.submitToken(token).statusCode(302).header("location", containsString(targetPath));
        HELPER.assertCookieMissing("quarkus-credential-request");
        HELPER.assertCookiePresent("quarkus-credential");

        HELPER.goTo(targetPath).statusCode(200).body(is(username + ":" + targetPath));
    }

}
