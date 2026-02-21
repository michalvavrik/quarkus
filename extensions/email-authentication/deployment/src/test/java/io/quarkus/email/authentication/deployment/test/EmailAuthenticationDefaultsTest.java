package io.quarkus.email.authentication.deployment.test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class EmailAuthenticationDefaultsTest {

    private static final TestEmailAuthenticationHelper testHelper = new TestEmailAuthenticationHelper(
            "/generate-email-authentication-token", "/j_security_check");

    @RegisterExtension
    private static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(TestTrustedIdentityProvider.class, TestEmailAuthenticationHelper.class));

    @BeforeEach
    void reset() {
        testHelper.clear();
    }

    @Test
    void testCompleteFlowSuccess() {
        String username = "Vaclav";
        TestTrustedIdentityProvider.reset().addUser(username);
        testHelper.requestTokenFor(username)
                .statusCode(302);
    }

}
