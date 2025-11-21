package io.quarkus.hibernate.orm.rest.data.panache.deployment.security;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasSize;

import jakarta.annotation.security.RolesAllowed;

import org.junit.jupiter.api.Test;

import io.quarkus.hibernate.orm.rest.data.panache.PanacheEntityResource;
import io.quarkus.rest.data.panache.ResourceProperties;

public class RolesAllowedPanacheResourceTest extends AbstractSecurityAnnotationTest {

    @ResourceProperties(path = "items")
    public interface ItemsResource extends PanacheEntityResource<Item, Long> {

        @RolesAllowed("user")
        boolean delete(Long id);
    }

    @Test
    void test() {
        // list method is not protected so we should get an HTTP 200 even if no user is specified
        given().accept("application/json")
                .when()
                .get("/items")
                .then()
                .statusCode(200)
                .body("$", hasSize(2));

        // delete method is protected so we should get an HTTP 401 when no user is specified
        given().accept("application/json")
                .when()
                .delete("/items/1")
                .then()
                .statusCode(401);

        // delete method is protected so we should get an HTTP 401 when a wrong username and password is specified
        given().auth().preemptive()
                .basic("foo", "foo2")
                .accept("application/json")
                .when()
                .delete("/items/1")
                .then()
                .statusCode(401);

        // delete method is protected so we should get an HTTP 403 when the 'user' role is missing
        given().auth().preemptive()
                .basic("bar", "bar")
                .accept("application/json")
                .when()
                .delete("/items/1")
                .then()
                .statusCode(403);

        // delete method is protected so we should get an HTTP 204 when the proper username and password are specified
        given().auth().preemptive()
                .basic("foo", "foo")
                .accept("application/json")
                .when()
                .delete("/items/1")
                .then()
                .statusCode(204);
    }

}
