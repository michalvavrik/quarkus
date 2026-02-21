package io.quarkus.email.authentication.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;

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

    static final String FROM = "security@quarkus.io";

    private final String tokenGenerationPath;
    private final String postLocation;
    private final String emailSubject;
    private final String emailTextStart;
    private CookieFilter cookieFilter;

    TestEmailAuthenticationHelper(String tokenGenerationPath, String postLocation, String emailSubject, String emailTextStart) {
        this.tokenGenerationPath = tokenGenerationPath;
        this.postLocation = postLocation;
        this.emailSubject = emailSubject;
        this.emailTextStart = emailTextStart;
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

    private static List<Mail> awaitEmailWithToken(MockMailbox mailbox, String address) {
        return Awaitility.await()
                .atMost(Duration.ofSeconds(10))
                .until(() -> mailbox.getMailsSentTo(address), Matchers.not(Matchers.emptyIterable()));
    }

    String assertEmailAndGetToken(MockMailbox mailbox, String emailAddress) {
        var emails = awaitEmailWithToken(mailbox, emailAddress);
        var firstMailAsserter = assertThat(emails).hasSize(1).first();
        firstMailAsserter.extracting(Mail::getSubject).isEqualTo(emailSubject);
        assertThat(firstMailAsserter.extracting(Mail::getText).actual()).startsWith(emailTextStart);
        String emailAuthToken = emails.get(0).getText()
                .trim()
                .transform(t -> {
                    var arr = t.split(" ");
                    return arr[arr.length - 1];
                });
        assertThat(emailAuthToken).isNotEmpty();
        return emailAddress;
    }
}
