package io.quarkus.csrf.reactive;

import static io.restassured.RestAssured.given;
import static io.restassured.RestAssured.when;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;

public class CsrfDevModeTest {

    @RegisterExtension
    static final QuarkusDevModeTest config = new QuarkusDevModeTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(TestResource.class)
                    .addAsResource("templates/csrfToken.html"));

    private final static String COOKIE_NAME = "csrf-token";

    @Test
    public void testCsrfConfigChange() {
        testForm();
    }

    private static void testForm() {
        String token = when()
                .get("/csrfTokenForm")
                .then()
                .statusCode(200)
                .cookie(COOKIE_NAME)
                .extract()
                .cookie(COOKIE_NAME);
        EncoderConfig encoderConfig = EncoderConfig.encoderConfig().encodeContentTypeAs("multipart/form-data",
                ContentType.TEXT);
        RestAssuredConfig restAssuredConfig = RestAssured.config().encoderConfig(encoderConfig);

        //no token
        given()
                .cookie(COOKIE_NAME, token)
                .config(restAssuredConfig)
                .formParam("name", "testName")
                .contentType(ContentType.URLENC)
                .when()
                .post("csrfTokenForm")
                .then()
                .statusCode(400);

        //wrong token
        given()
                .cookie(COOKIE_NAME, token)
                .config(restAssuredConfig)
                .formParam(COOKIE_NAME, "WRONG")
                .formParam("name", "testName")
                .contentType(ContentType.URLENC)
                .when()
                .post("csrfTokenForm")
                .then()
                .statusCode(400);

        //valid token
        given()
                .cookie(COOKIE_NAME, token)
                .config(restAssuredConfig)
                .formParam(COOKIE_NAME, token)
                .formParam("name", "testName")
                .contentType(ContentType.URLENC)
                .when()
                .post("csrfTokenForm")
                .then()
                .statusCode(200)
                .body(Matchers.equalTo("testName"));
    }

    @Path("/csrfTokenForm")
    public static class TestResource {

        @Inject
        Template csrfToken;

        @GET
        @Produces(MediaType.TEXT_HTML)
        public TemplateInstance getCsrfTokenForm() {
            return csrfToken.instance();
        }

        @POST
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.TEXT_PLAIN)
        public Uni<String> postCsrfTokenForm(@FormParam("name") String userName) {
            return Uni.createFrom().item(userName);
        }
    }
}
