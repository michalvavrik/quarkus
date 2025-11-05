package io.quarkus.it.hibernate.processor.data;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkus.it.hibernate.processor.data.pudefault.MyEntity;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;

@QuarkusTest
public class HibernateOrmDataSecurityTest {

    // FIXME: impl. me!
    // FIXME: impl. me!

    // FIXME: what needs to be done:
    //   - collect implementations
    //   - know what secured methods their interface has including ones inherited from
    //   - we add annotation collections, we need to cover also repeatable annotations
    //   - and we create the transformation when actually necessary based on index inside the build item

    // TODO: what about abstract classes impl. that interfaces, like abstract methods and non-abstract methods
    // TODO: what needs to be done
    //  - delete these notes
    //  - document limitations for Jakarta Data and link it to the authz endpoints note re inheritance
    //  - write tests, do not forget about interface extended by interface, class-level annotations,
    //  static methods, default methods, overloaded methods, methods already annotated with sec annotation,
    //  permissions allowed repeatable and not repeatable, permissions allowed meta annotations,
    //  combinations between class-level and method-level annotations transformed/not transformed
    //  - finish gathering of annotation instances for meta-annotations and repeatable permissions allowed
    //  - review gathering of security checks annotations
    //  - run all the related tests
    // TODO: verify impl. of impl.
    // TODO: add method with the same signature
    // TODO: what if it is the default method?
    // TODO: what if it is overloaded?
    // TODO: what if it is present on multiple interfaces with the same signature?
    // TODO: DOCUMENT THIS FOR JAKARTA DATA ONLY! it has it's limitations and it is not perfect
    // TODO: what about static methods on interface?
    // TODO: what about private methods
    // TODO: make sure it is not already added (how, maybe Set? maybe go over the annotation instance again? maybe cache it?)

    // FIXME: can the transformation be null? oh yeah, if there is no implementation!

    @ValueSource(strings = { "/data", "/data/other" })
    @ParameterizedTest
    public void testEntities(String root) {
        // Create/retrieve
        given()
                .pathParam("name", "foo")
                .contentType(ContentType.JSON)
                .when().get(root + "/by/name/{name}")
                .then()
                .statusCode(404);
        given()
                .contentType(ContentType.JSON)
                .when().get(root)
                .then()
                .statusCode(200)
                .body(equalTo("[]"));
        given()
                .body(new MyEntity("foo"))
                .contentType(ContentType.JSON)
                .when().post(root)
                .then()
                .statusCode(204);
        given()
                .pathParam("name", "foo")
                .contentType(ContentType.JSON)
                .when().get(root + "/by/name/{name}")
                .then()
                .statusCode(200);
        given()
                .contentType(ContentType.JSON)
                .when().get(root)
                .then()
                .statusCode(200)
                .body(containsString("\"foo\""));

        // Update
        given()
                .pathParam("name", "bar")
                .contentType(ContentType.JSON)
                .when().get(root + "/by/name/{name}")
                .then()
                .statusCode(404);
        given()
                .pathParam("before", "foo")
                .pathParam("after", "bar")
                .contentType(ContentType.JSON)
                .when().post(root + "/rename/{before}/to/{after}")
                .then()
                .statusCode(204);
        given()
                .pathParam("name", "bar")
                .contentType(ContentType.JSON)
                .when().get(root + "/by/name/{name}")
                .then()
                .statusCode(200);

        // Delete
        given()
                .pathParam("name", "bar")
                .contentType(ContentType.JSON)
                .when().delete(root + "/by/name/{name}")
                .then()
                .statusCode(204);
        given()
                .pathParam("name", "bar")
                .contentType(ContentType.JSON)
                .when().get(root + "/by/name/{name}")
                .then()
                .statusCode(404);
    }

    @Test
    public void testSqlOnly() {
        given()
                .pathParam("name", "admin")
                .contentType(ContentType.JSON)
                .when().get("/data/sqlonly/myuser/by/username/{name}")
                .then()
                .statusCode(404);
        given()
                .pathParam("id", 42)
                .contentType(ContentType.JSON)
                .body("{\"username\":\"admin\",\"role\":\"admin\"}")
                .when().put("/data/sqlonly/myuser/{id}")
                .then()
                .statusCode(204);
        given()
                .pathParam("name", "admin")
                .contentType(ContentType.JSON)
                .when().get("/data/sqlonly/myuser/by/username/{name}")
                .then()
                .statusCode(200)
                .body(equalTo("{\"id\":42,\"username\":\"admin\",\"role\":\"admin\"}"));
    }
}
