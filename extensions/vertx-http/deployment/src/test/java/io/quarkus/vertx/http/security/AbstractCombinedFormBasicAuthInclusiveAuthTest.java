package io.quarkus.vertx.http.security;

import static org.hamcrest.Matchers.equalTo;

import java.util.Map;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.quarkus.security.test.utils.TestIdentityController;
import io.quarkus.security.test.utils.TestIdentityProvider;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;

abstract class AbstractCombinedFormBasicAuthInclusiveAuthTest {

    protected static QuarkusUnitTest createTestApp(Map<String, String> additionalProperties) {
        var app = new QuarkusUnitTest().withApplicationRoot(jar -> jar
                .addClasses(TestIdentityProvider.class, TestTrustedIdentityProvider.class, TestIdentityController.class,
                        PathHandler.class)
                .addAsResource(new StringAsset("""
                        quarkus.http.auth.basic=true
                        quarkus.http.auth.realm=TestRealm
                        quarkus.http.auth.form.enabled=true
                        quarkus.http.auth.form.login-page=
                        quarkus.http.auth.form.error-page=
                        quarkus.http.auth.form.landing-page=
                        quarkus.http.auth.policy.r1.roles-allowed=admin
                        quarkus.http.auth.permission.roles1.paths=/admin
                        quarkus.http.auth.permission.roles1.policy=r1
                        """), "application.properties"));
        additionalProperties.forEach(app::overrideRuntimeConfigKey);
        return app;
    }

    @BeforeAll
    static void setup() {
        TestIdentityController.resetRoles()
                .add("admin", "admin", "admin");
    }

    @Test
    void testFormBasedAuthOnlyFails() {
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
                .statusCode(200);

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get("/admin")
                .then()
                .statusCode(401);
    }

    @Test
    void testBasicAuthOnlyFails() {
        RestAssured
                .given()
                .auth().preemptive().basic("admin", "admin")
                .redirects().follow(false)
                .when()
                .get("/admin")
                .then()
                .statusCode(401);
    }

    @Test
    public void testBasicAndFormAuthTogetherSucceeds() {
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
                .statusCode(200);

        RestAssured
                .given()
                .filter(cookies)
                .auth().preemptive().basic("admin", "admin")
                .when()
                .get("/admin")
                .then()
                .statusCode(200)
                .body(equalTo("admin:/admin"));
    }
}
