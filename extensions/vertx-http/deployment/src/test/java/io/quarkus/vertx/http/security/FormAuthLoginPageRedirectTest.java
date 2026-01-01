package io.quarkus.vertx.http.security;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.test.utils.TestIdentityController;
import io.quarkus.security.test.utils.TestIdentityProvider;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.matcher.RestAssuredMatchers;

public class FormAuthLoginPageRedirectTest {

    @RegisterExtension
    static QuarkusUnitTest test = new QuarkusUnitTest().setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
            .addClasses(TestIdentityProvider.class, TestTrustedIdentityProvider.class, TestIdentityController.class,
                    PathHandler.class)
            .addAsResource(new StringAsset("""
                    quarkus.http.auth.basic=true
                    quarkus.http.auth.form.enabled=true
                    quarkus.http.auth.form.login-page=/login
                    quarkus.http.auth.form.error-page=/login?failed
                    quarkus.http.auth.form.landing-page=landing
                    quarkus.http.auth.policy.r1.roles-allowed=admin
                    quarkus.http.auth.permission.roles1.paths=/*
                    quarkus.http.auth.permission.roles1.policy=r1
                    quarkus.http.auth.permission.public.paths=login
                    quarkus.http.auth.permission.public.policy=permit
                    quarkus.http.auth.permission.public.methods=GET
                    """), "application.properties"));

    @BeforeAll
    public static void setup() {
        TestIdentityController.resetRoles()
                .add("admin", "admin", "admin")
                .add("test", "test", "admin");
    }

    @Test
    public void testFormBasedAuthSuccess() {
        CookieFilter cookies = new CookieFilter();
        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get("/admin")
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/login"))
                .cookie("quarkus-redirect-location",
                        RestAssuredMatchers.detailedCookie().value(containsString("/admin")).secured(false));

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
                .header("location", containsString("/admin"))
                .cookie("quarkus-credential",
                        RestAssuredMatchers.detailedCookie().value(notNullValue()).secured(false));

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get("/admin")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalTo("admin:/admin"));

        //now authenticate with a different user
        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .formParam("j_username", "test")
                .formParam("j_password", "test")
                .post("/j_security_check")
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/landing"))
                .cookie("quarkus-credential",
                        RestAssuredMatchers.detailedCookie().value(notNullValue()).secured(false));

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get("/admin")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalTo("test:/admin"));

    }

    @Test
    public void testFormBasedAuthSuccessLandingPage() {
        CookieFilter cookies = new CookieFilter();
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
                .header("location", containsString("/landing"))
                .cookie("quarkus-credential", notNullValue());
    }

    @Test
    public void testFormAuthFailure() {
        CookieFilter cookies = new CookieFilter();
        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .formParam("j_username", "admin")
                .formParam("j_password", "wrongpassword")
                .post("/j_security_check")
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/login?failed"));
    }

    @Test
    public void testLoginRedirect() {
        RestAssured
                .given()
                .get("/login")
                .then()
                .assertThat()
                .statusCode(200)
                .body(Matchers.notNullValue());
    }

    @Test
    public void testLoginRedirectWithQuery() {
        RestAssured
                .given()
                .get("/login?some-thing=1234")
                .then()
                .assertThat()
                .statusCode(200)
                .body(Matchers.notNullValue());
    }
}
