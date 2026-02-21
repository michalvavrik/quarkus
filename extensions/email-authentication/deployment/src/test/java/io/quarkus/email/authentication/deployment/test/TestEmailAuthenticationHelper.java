package io.quarkus.email.authentication.deployment.test;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;

import org.apache.http.cookie.Cookie;
import org.awaitility.Awaitility;
import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;

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
        this.cookieFilter = new CookieFilter();
    }

    ValidatableResponse requestTokenFor(String username) {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        return RestAssured.given()
                .filter(cookieFilter)
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
        return emailAuthToken;
    }

    Consumer<JavaArchive> getAppConfig() {
        return (jar) -> jar
                .addAsResource(new StringAsset("""
                        quarkus.mailer.from=%s
                        quarkus.http.auth.permission.secured.paths=/secured*
                        quarkus.http.auth.permission.secured.policy=authenticated
                        quarkus.http.auth.permission.admin.paths=/secured/admin*
                        quarkus.http.auth.permission.admin.policy=admin
                        quarkus.http.auth.policy.admin.roles-allowed=admin
                        """.formatted(FROM)), "application.properties")
                .addClasses(TestTrustedIdentityProvider.class, TestEmailAuthenticationHelper.class, TestPathHandler.class);
    }

    ValidatableResponse goTo(String targetPath) {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        return RestAssured
                .given()
                .redirects().follow(false)
                .filter(cookieFilter)
                .get(targetPath)
                .then();
    }

    void assertCookie(String cookieName, String targetPath) {
        var cookieAsserter = assertThat(cookieFilter.getCookieStore().getCookies());
        cookieAsserter.isNotEmpty();
        cookieAsserter.extracting(Cookie::getName).anyMatch(cookieName::equalsIgnoreCase);
        var cookie = cookieAsserter.actual().stream().filter(c -> cookieName.equalsIgnoreCase(c.getName()))
                .findFirst().get();
        assertThat(cookie).extracting(Cookie::getValue).asString().contains(targetPath);
    }
}
