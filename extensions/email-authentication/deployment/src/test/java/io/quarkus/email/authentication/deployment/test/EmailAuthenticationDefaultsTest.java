package io.quarkus.email.authentication.deployment.test;

import static io.quarkus.email.authentication.deployment.test.TestEmailAuthenticationHelper.FROM;

import jakarta.inject.Inject;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.mailer.MockMailbox;
import io.quarkus.test.QuarkusUnitTest;

class EmailAuthenticationDefaultsTest {

    private static final TestEmailAuthenticationHelper testHelper = new TestEmailAuthenticationHelper(
            "/generate-email-authentication-token", "/j_security_check", "Your verification code", "Your verification code is");

    @RegisterExtension
    private static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(TestTrustedIdentityProvider.class, TestEmailAuthenticationHelper.class))
            .withConfiguration("""
                    quarkus.mailer.from=%s
                    """.formatted(FROM));

    @Inject
    MockMailbox mailbox;

    @BeforeEach
    void reset() {
        testHelper.clear();
    }

    @Test
    void testCompleteFlowSuccess() {
        String username = "Vaclav";
        String emailAddress = "test-vaclav@quarkus.io";
        TestTrustedIdentityProvider.reset().addUser(username, emailAddress);
        testHelper.requestTokenFor(username).statusCode(302);
        String token = testHelper.assertEmailAndGetToken(mailbox, emailAddress);
    }

}
