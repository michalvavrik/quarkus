package org.michalvavrik.qute.development;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class ExampleResourceTest {

    @Test
    public void testHelloEndpoint() {
        given()
                .when().get("/hello")
                .then()
                .statusCode(200)
                .body(is("hello"));
    }

    @Test
    public void testTemplate() {
        given()
                .when().get("/hello/template")
                .then()
                .statusCode(200)
                .body(is("Basic Qute Template!"));
    }

}
