package io.quarkus.email.authentication.deployment.test;

import java.time.Duration;
import java.util.List;

import org.awaitility.Awaitility;
import org.hamcrest.Matchers;

import io.quarkus.mailer.Mail;
import io.quarkus.mailer.MockMailbox;
import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.ValidatableResponse;

final class TestEmailAuthenticationHelper {

    private final String tokenGenerationPath;
    private final String postLocation;
    private CookieFilter cookieFilter;

    TestEmailAuthenticationHelper(String tokenGenerationPath, String postLocation) {
        this.tokenGenerationPath = tokenGenerationPath;
        this.postLocation = postLocation;
    }

    ValidatableResponse requestTokenFor(String username) {
        cookieFilter = new CookieFilter();
        return RestAssured.given()
                .formParam("j_username", username)
                .post(tokenGenerationPath)
                .then();
    }

    void clear() {
        cookieFilter = new CookieFilter();
    }

    static List<Mail> awaitEmailWithToken(MockMailbox mailbox, String address) {
        return Awaitility.await()
                .atMost(Duration.ofSeconds(10))
                .until(() -> mailbox.getMailsSentTo(address), Matchers.not(Matchers.emptyIterable()));
    }
}
