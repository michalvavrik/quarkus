package io.quarkus.email.authentication.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;

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

    private static final TestEmailAuthenticationHelper TEST_HELPER = new TestEmailAuthenticationHelper(
            "/generate-email-authentication-token", "/j_security_check", "Your verification code", "Your verification code is");

    @RegisterExtension
    static final QuarkusUnitTest APP = new QuarkusUnitTest().withApplicationRoot(TEST_HELPER.getAppConfig());

    @Inject
    MockMailbox mailbox;

    @BeforeEach
    void reset() {
        TEST_HELPER.clear();
    }

    @Test
    void testCompleteFlowSuccess() {
        String username = "Vaclav";
        String emailAddress = "test-vaclav@quarkus.io";
        TestTrustedIdentityProvider.reset().addUser(username, emailAddress);
        TEST_HELPER.requestTokenFor(username).statusCode(302);
        String token = TEST_HELPER.assertEmailAndGetToken(mailbox, emailAddress);
        assertThat(token).hasSize(15);
        for (char c : token.toCharArray()) {
            assertThat(Character.toString(c)).isSubstringOf(ALLOWED_CHARS);
        }
    }

}
