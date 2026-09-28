package io.quarkus.vertx.http;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;

class SemicolonQueryParamRequestParamsTest {

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(Routes.class))
            .withRuntimeConfiguration("""
                    quarkus.http.use-semicolon-as-query-param-delimiter=false
                    """);

    @Test
    void testGetParamTreatsSemicolonAsLiteral() {
        given()
                .urlEncodingEnabled(false)
                .get("/get-param?a=1;b=2")
                .then()
                .statusCode(200)
                .body(is("a=1;b=2|b=null"));
        /*
         * FAILS WITH:
         * [ERROR] SemicolonQueryParamRequestParamsTest.testGetParamTreatsSemicolonAsLiteral:36 1 expectation failed.
         * Response body doesn't match expectation.
         * Expected: is "a=1;b=2|b=null"
         * Actual: a=1|b=2
         */
    }

    @Test
    void testParamsTreatsSemicolonAsLiteral() {
        given()
                .urlEncodingEnabled(false)
                .get("/params?a=1;b=2")
                .then()
                .statusCode(200)
                .body(is("a=1;b=2|b=null"));
        /*
         * FAILS WITH:
         * [ERROR] SemicolonQueryParamRequestParamsTest.testParamsTreatsSemicolonAsLiteral:46 1 expectation failed.
         * Response body doesn't match expectation.
         * Expected: is "a=1;b=2|b=null"
         * Actual: a=1|b=2
         */
    }

    @Test
    void testQueryParamsTreatsSemicolonAsLiteralAfterParamsCall() {
        given()
                .urlEncodingEnabled(false)
                .get("/query-params-after-params?a=1;b=2")
                .then()
                .statusCode(200)
                .body(is("a=1;b=2|b=null"));
        /*
         * FAILS WITH:
         * [ERROR] SemicolonQueryParamRequestParamsTest.testQueryParamsTreatsSemicolonAsLiteralAfterParamsCall:56 1 expectation
         * failed.
         * Response body doesn't match expectation.
         * Expected: is "a=1;b=2|b=null"
         * Actual: a=1|b=2
         */
    }

    @Test
    void testQueryParamsTreatsSemicolonAsLiteralBeforeParamsCall() {
        given()
                .urlEncodingEnabled(false)
                .get("/query-params-before-params?a=1;b=2")
                .then()
                .statusCode(200)
                .body(is("a=1;b=2|b=null"));
    }

    @Test
    void testQueryParamsTreatsSemicolonAsLiteralWithJsonBody() {
        given()
                .urlEncodingEnabled(false)
                .contentType("application/json")
                .body("{}")
                .post("/body?a=1;b=2")
                .then()
                .statusCode(200)
                .body(is("a=1;b=2|b=null"));
    }

    @Test
    void testQueryParamsTreatsSemicolonAsLiteralWithFormBodyWithoutMerge() {
        given()
                .urlEncodingEnabled(false)
                .formParam("c", "3")
                .post("/form-body-without-merge?a=1;b=2")
                .then()
                .statusCode(200)
                .body(is("a=1;b=2|b=null"));
    }

    @ApplicationScoped
    static class Routes {
        public void register(@Observes Router router) {
            router.route("/get-param").handler(rc -> {
                String a = rc.request().getParam("a");
                String b = rc.request().getParam("b");
                rc.response().end("a=" + a + "|b=" + b);
            });
            router.route("/params").handler(rc -> {
                MultiMap params = rc.request().params();
                rc.response().end("a=" + params.get("a") + "|b=" + params.get("b"));
            });
            router.route("/query-params-after-params").handler(rc -> {
                // must not change how the query parameters below are decoded
                rc.request().params();
                String a = rc.queryParams().get("a");
                String b = rc.queryParams().get("b");
                rc.response().end("a=" + a + "|b=" + b);
            });
            router.route("/query-params-before-params").handler(rc -> {
                // decoded and cached here, so the params() call below cannot change them
                String a = rc.queryParams().get("a");
                rc.request().params();
                String b = rc.queryParams().get("b");
                rc.response().end("a=" + a + "|b=" + b);
            });
            Handler<RoutingContext> echoQueryParams = rc -> rc.response()
                    .end("a=" + rc.queryParams().get("a") + "|b=" + rc.queryParams().get("b"));
            // BodyHandler only calls params() when it merges the attributes of a form or multipart body
            router.post("/body").handler(BodyHandler.create()).handler(echoQueryParams);
            router.post("/form-body-without-merge").handler(BodyHandler.create().setMergeFormAttributes(false))
                    .handler(echoQueryParams);
        }
    }
}
