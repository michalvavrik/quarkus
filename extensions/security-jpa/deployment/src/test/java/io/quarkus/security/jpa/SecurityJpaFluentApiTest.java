package io.quarkus.security.jpa;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import java.time.Duration;

import jakarta.enterprise.event.Observes;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.security.Form;
import io.quarkus.vertx.http.security.HttpSecurity;
import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;

public class SecurityJpaFluentApiTest {

    @RegisterExtension
    static QuarkusUnitTest test = new QuarkusUnitTest().setArchiveProducer(() -> ShrinkWrap
            .create(JavaArchive.class)
            .addClasses(SingleRoleSecuredServlet.class, TestApplication.class, RolesEndpointClassLevel.class,
                    ParametrizedPathsResource.class, SubjectExposingResource.class, MinimalUserEntity.class,
                    SecurityJpaConfiguration.class)
            .addAsResource("minimal-config/import.sql", "import.sql")
            .addAsResource(new StringAsset("""
                    quarkus.datasource.db-kind=h2
                    quarkus.datasource.username=sa
                    quarkus.datasource.password=sa
                    quarkus.datasource.jdbc.url=jdbc:h2:mem:minimal-config
                    quarkus.hibernate-orm.sql-load-script=import.sql
                    quarkus.hibernate-orm.schema-management.strategy=drop-and-create
                    """), "application.properties"));

    @Test
    void testFormBasedAuthentication() {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        CookieFilter cookies = new CookieFilter();
        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get("/servlet-secured")
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/login"))
                .cookie("quarkus-redirect-location", containsString("/servlet-secured"));

        // test with a non-existent user
        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .formParam("j_username", "dummy")
                .formParam("j_password", "dummy")
                .post("/j_security_check")
                .then()
                .assertThat()
                .statusCode(302);

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .formParam("j_username", "user")
                .formParam("j_password", "user")
                .post("/j_security_check")
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/servlet-secured"))
                .cookie("laitnederc-sukrauq", notNullValue());

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get("/servlet-secured")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalTo("A secured message"));
    }

    public static class SecurityJpaConfiguration {

        void configure(@Observes HttpSecurity httpSecurity) {
            var form = Form.builder()
                    .loginPage("login")
                    .errorPage("error")
                    .landingPage("landing")
                    .cookieName("laitnederc-sukrauq")
                    .newCookieInterval(Duration.ofSeconds(5))
                    .timeout(Duration.ofSeconds(5))
                    .encryptionKey("CHANGEIT-CHANGEIT-CHANGEIT-CHANGEIT-CHANGEIT")
                    .build();
            var jpa = SecurityJpa.jpa();
            httpSecurity
                    .mechanism(form, jpa)
                    .path("/admin%E2%9D%A4").roles("admin");
        }

    }

}
