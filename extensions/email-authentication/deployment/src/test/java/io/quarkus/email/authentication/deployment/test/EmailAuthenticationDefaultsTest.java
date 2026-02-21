package io.quarkus.email.authentication.deployment.test;

import static io.quarkus.email.authentication.deployment.test.TestEmailAuthenticationHelper.awaitEmailWithToken;

import java.util.List;

import jakarta.inject.Inject;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.mailer.Mail;
import io.quarkus.mailer.MockMailbox;
import io.quarkus.test.QuarkusUnitTest;

class EmailAuthenticationDefaultsTest {

    private static final TestEmailAuthenticationHelper testHelper = new TestEmailAuthenticationHelper(
            "/generate-email-authentication-token", "/j_security_check");

    @RegisterExtension
    private static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(TestTrustedIdentityProvider.class, TestEmailAuthenticationHelper.class))
            .withConfiguration("""
                    quarkus.mailer.from=test-security@quarkus.io
                    """);

    @Inject
    MockMailbox mailbox;

    @BeforeEach
    void reset() {
        testHelper.clear();
    }

    @Test
    void testCompleteFlowSuccess() {
        String username = "Vaclav";
        TestTrustedIdentityProvider.reset().addUser(username);
        testHelper.requestTokenFor(username).statusCode(302);
        List<Mail> emails = awaitEmailWithToken(mailbox, username);
        emails.forEach(e -> System.out.println("///// email is " + e)); // FIXME: remove me!
    }

}
