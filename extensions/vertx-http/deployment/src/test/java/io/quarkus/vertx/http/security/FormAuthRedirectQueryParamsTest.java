package io.quarkus.vertx.http.security;

import static io.restassured.matcher.RestAssuredMatchers.detailedCookie;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import java.time.Duration;

import jakarta.enterprise.event.Observes;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.test.utils.TestIdentityController;
import io.quarkus.security.test.utils.TestIdentityProvider;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.FormAuthConfig.CookieSameSite;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;

class FormAuthRedirectQueryParamsTest {

    @RegisterExtension
    static final QuarkusUnitTest test = new QuarkusUnitTest().withApplicationRoot(jar -> jar
            .addClasses(TestIdentityProvider.class, TestIdentityController.class, TestTrustedIdentityProvider.class,
                    PathHandler.class, HttpSecurityConfigurator.class)
            .addAsResource(new StringAsset(""), "application.properties"));

    @BeforeAll
    static void setup() {
        TestIdentityController.resetRoles()
                .add("admin", "admin", "admin");
    }

    @Test
    void testQueryParamsPassedThrough() {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        CookieFilter cookies = new CookieFilter();
        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get("/admin❤?jfwid=1234")
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/login"))
                .cookie("quarkus-redirect-location",
                        detailedCookie().value(containsString("/admin%E2%9D%A4?jfwid=1234")).sameSite("Lax"));

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .formParam("j_username", "admin")
                .formParam("j_password", "admin")
                .post("/j_security_check")
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/admin%E2%9D%A4?jfwid=1234"))
                .cookie("laitnederc-sukrauq", detailedCookie().value(notNullValue())
                        .httpOnly(true).sameSite("Lax").maxAge(120));

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get("/admin❤?jfwid=1234")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalTo("admin:/admin%E2%9D%A4"));

    }

    static class HttpSecurityConfigurator {

        void configureHttpPermission(@Observes HttpSecurity httpSecurity) {
            httpSecurity.path("/admin%E2%9D%A4").roles("admin");
        }

        void configureFormAuthentication(@Observes HttpSecurity httpSecurity) {
            HttpAuthenticationMechanism formMechanism = Form.builder()
                    .loginPage("login")
                    .errorPage("error")
                    .landingPage("landing")
                    .timeout(Duration.ofSeconds(2))
                    .newCookieInterval(Duration.ofSeconds(1))
                    .cookieName("laitnederc-sukrauq")
                    .cookieSameSite(CookieSameSite.LAX)
                    .httpOnlyCookie()
                    .cookieMaxAge(Duration.ofMinutes(2))
                    .encryptionKey("CHANGEIT-CHANGEIT-CHANGEIT-CHANGEIT-CHANGEIT")
                    .build();
            httpSecurity.mechanism(formMechanism);
        }
    }
}
