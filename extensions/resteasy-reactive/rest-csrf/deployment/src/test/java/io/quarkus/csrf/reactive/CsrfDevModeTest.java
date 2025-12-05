package io.quarkus.csrf.reactive;

import static io.restassured.RestAssured.given;
import static io.restassured.RestAssured.when;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import io.smallrye.mutiny.Uni;

public class CsrfDevModeTest {

    private final static String COOKIE_NAME = "csrf-token";

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(TestResource.class)
                    .addAsResource(new StringAsset("quarkus.rest-csrf.token-size=32"), "application.properties")
                    .addAsResource("templates/csrfToken.html"));

    @Test
    public void testCsrfConfigChange() {
        String token = getToken();
        testForm(token).statusCode(200).body(Matchers.equalTo("testName"));
        assertTokenSize(token, 32);
        assertTokenSizeLesserThan(token, 64);
        test.modifyResourceFile("application.properties", s -> s.replace("32", "64"));
        testForm(token).statusCode(400);
        token = getToken(token);
        testForm(token).statusCode(200).body(Matchers.equalTo("testName"));
        assertTokenSize(token, 64);
    }

    private static void assertTokenSize(String token, int expectedTokenSizeInBytes) {
        byte[] tokenInBytes = token.getBytes();
        int actualTokenSizeInBytes = tokenInBytes.length;
        // encoded token bytes are always of equal or greater length than expected bytes
        assertTrue(actualTokenSizeInBytes >= expectedTokenSizeInBytes,
                () -> "Expected token size in bytes to be at least %d, but was %d: %s".formatted(expectedTokenSizeInBytes,
                        actualTokenSizeInBytes, token));
    }

    private static void assertTokenSizeLesserThan(String token, int expectedMaxTokenSize) {
        byte[] tokenInBytes = token.getBytes();
        int actualTokenSizeInBytes = tokenInBytes.length;
        assertTrue(actualTokenSizeInBytes < expectedMaxTokenSize,
                () -> "Expected token size in bytes to be lesser than %d, but was %d: %s".formatted(expectedMaxTokenSize,
                        actualTokenSizeInBytes, token));
    }

    private static ValidatableResponse testForm(String token) {
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

        //given token
        return given()
                .cookie(COOKIE_NAME, token)
                .config(restAssuredConfig)
                .formParam(COOKIE_NAME, token)
                .formParam("name", "testName")
                .contentType(ContentType.URLENC)
                .when()
                .post("csrfTokenForm")
                .then();
    }

    private static String getToken(String oldToken) {
        return RestAssured.given()
                .cookie(COOKIE_NAME, oldToken)
                .get("/csrfTokenForm")
                .then()
                .statusCode(200)
                .cookie(COOKIE_NAME)
                .extract()
                .cookie(COOKIE_NAME);
    }

    private static String getToken() {
        return when()
                .get("/csrfTokenForm")
                .then()
                .statusCode(200)
                .cookie(COOKIE_NAME)
                .extract()
                .cookie(COOKIE_NAME);
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
