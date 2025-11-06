package io.quarkus.it.hibernate.processor.data;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

import io.quarkus.it.hibernate.processor.data.pudefault.MyEntity;
import io.quarkus.it.hibernate.processor.data.security.SecuredMyEntityResource;
import io.quarkus.test.common.http.TestHTTPEndpoint;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;

@QuarkusTest
public class HibernateOrmDataSecurityTest {

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
    // TODO: DOCUMENT THIS FOR JAKARTA DATA ONLY! it has it's limitations and it is not perfect
    // TODO: what if the method is present on multiple interfaces with the same signature

    @TestSecurity(user = "hudson", roles = "admin")
    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    @Test
    void testMethodLevelRolesAllowed() {
        try {
            // this Jakarta Data repository requires "root" role, but we have "admin"
            given()
                    .body(new MyEntity("foo"))
                    .contentType(ContentType.JSON)
                    .when().post("/insert-root")
                    .then()
                    .statusCode(403);
            findEntityByName("foo").statusCode(404);

            // this Jakarta Data repository requires "admin" role and we have it
            given()
                    .body(new MyEntity("foo"))
                    .contentType(ContentType.JSON)
                    .when().post("/insert-admin")
                    .then()
                    .statusCode(204);
            findEntityByName("foo").statusCode(200);
        } finally {
            deleteEntityByName("foo");
        }
    }

    @TestSecurity(user = "hudson", roles = "trump")
    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    @Test
    void testMethodLevelRolesAllowedPropertyExpansion() {
        try {
            // prepare some entities
            createEntityPublic("foo");
            createEntityPublic("bar");

            // requires role 'bush', but we have 'trump'
            given()
                    .get("/list-all-george")
                    .then()
                    .statusCode(403);
            // requires role 'trump' as property expression was expanded: donald -> trump
            given()
                    .get("/list-all-donald")
                    .then()
                    .statusCode(200)
                    .body("size()", is(2));
        } finally {
            deleteEntityByName("foo");
            deleteEntityByName("bar");
        }
    }

    @TestSecurity(user = "hudson", permissions = "rename-2")
    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    @Test
    void testMethodLevelSinglePermissionsAllowed() {
        String entityName = "bar";
        try {
            createEntityPublic(entityName);
            findEntityByName(entityName).statusCode(200);
            findEntityByName("foo").statusCode(404);

            // this update operation requires permission 'rename-1', but we have 'rename-2'
            given()
                    .pathParam("before", entityName)
                    .pathParam("after", "foo")
                    .contentType(ContentType.JSON)
                    .post("/rename-1/{before}/to/{after}")
                    .then()
                    .statusCode(403);
            // this update operation requires permission 'rename-2' and we have it
            given()
                    .pathParam("before", entityName)
                    .pathParam("after", "foo")
                    .contentType(ContentType.JSON)
                    .post("/rename-2/{before}/to/{after}")
                    .then()
                    .statusCode(204);
            entityName = "foo";
            // check update succeeded
            findEntityByName("bar").statusCode(404);
            findEntityByName(entityName).statusCode(200);
        } finally {
            deleteEntityByName(entityName);
        }
    }

    @TestSecurity(user = "hudson", permissions = { "rename-2", "rename-3" })
    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    @Test
    void testMethodLevelMultiplePermissionsAllowed() {
        String entityName1 = "foo";
        String entityName2 = "bar";
        try {
            // create 2 entities we will later try to rename
            createEntityPublic(entityName1);
            findEntityByName(entityName1).statusCode(200);
            createEntityPublic(entityName2);
            findEntityByName(entityName2).statusCode(200);

            // this repository method requires permissions 'rename-1' and 'rename-2', but we only have 'rename-2'
            given()
                    .queryParam("before", entityName1, entityName2)
                    .queryParam("after", "foobar", "baz")
                    .contentType(ContentType.JSON)
                    .post("/rename-all-perms-1-2")
                    .then()
                    .statusCode(403);
            findEntityByName("foobar").statusCode(404);
            findEntityByName("baz").statusCode(404);
            // this repository method requires permissions 'rename-2' and 'rename-3', and we have them
            given()
                    .queryParam("before", entityName1, entityName2)
                    .queryParam("after", "foobar", "baz")
                    .contentType(ContentType.JSON)
                    .post("/rename-all-perms-2-3")
                    .then()
                    .statusCode(204);
            entityName1 = "foobar";
            entityName2 = "baz";
            findEntityByName(entityName1).statusCode(200);
            findEntityByName(entityName2).statusCode(200);
        } finally {
            deleteEntityByName(entityName1);
            deleteEntityByName(entityName2);
        }
    }

    @Test
    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    void testOverloadedSecuredMethod() {
        /*
         * Here we test 2 repository methods with the same name defined on the same interface, only one must be secured.
         *
         * @PermissionsAllowed("rename-overloaded")
         *
         * @Update
         * void renameOverloaded(List<MyEntity> entities);
         *
         * @Update
         * void renameOverloaded(MyEntity entity);
         */
        String entityName = "baz";
        try {
            createEntityPublic(entityName);
            findEntityByName(entityName).statusCode(200);

            given()
                    .queryParam("before", entityName)
                    .queryParam("after", "foobar")
                    .contentType(ContentType.JSON)
                    .post("/rename-overloaded-secured")
                    .then()
                    .statusCode(401);
            findEntityByName("foobar").statusCode(404);
            given()
                    .queryParam("before", entityName)
                    .queryParam("after", "foobar")
                    .contentType(ContentType.JSON)
                    .post("/rename-overloaded-public")
                    .then()
                    .statusCode(204);
            entityName = "foobar";
            findEntityByName(entityName).statusCode(200);
        } finally {
            deleteEntityByName(entityName);
        }
    }

    @TestSecurity(user = "hudson", permissions = "write-2")
    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    @Test
    void testMethodLevelPermissionsAllowedMetaAnnotation() {
        String entityName = "baz";
        try {
            // @CanWrite1 requires permission 'write-1', but we have 'write-2'
            given()
                    .body(new MyEntity(entityName))
                    .contentType(ContentType.JSON)
                    .when().post("/insert-all-1")
                    .then()
                    .statusCode(403);
            findEntityByName(entityName).statusCode(404);
            // @CanWrite2 requires permission 'write-2', and we have it
            given()
                    .body(new MyEntity(entityName))
                    .contentType(ContentType.JSON)
                    .when().post("/insert-all-2")
                    .then()
                    .statusCode(204);
            findEntityByName(entityName).statusCode(200);
        } finally {
            deleteEntityByName(entityName);
        }
    }

    @TestSecurity(user = "hudson")
    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    @Test
    void testMethodLevelDenyAll() {
        given()
                .body(new MyEntity("foo"))
                .contentType(ContentType.JSON)
                .when().post("/insert-deny-all")
                .then()
                .statusCode(403);
        findEntityByName("foo").statusCode(404);
    }

    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    @Test
    void testMethodLevelAuthenticated() {
        given()
                .body(new MyEntity("foo"))
                .contentType(ContentType.JSON)
                .when().post("/insert-authenticated")
                .then()
                .statusCode(401);
        findEntityByName("foo").statusCode(404);
    }

    @Test
    void testClassLevelRolesAllowed() {

    }

    @Test
    void testClassLevelPermissionsAllowed() {

    }

    @Test
    void testClassLevelPermissionsAllowedMetaAnnotation() {

    }

    @Test
    void testClassLevelAuthenticated() {

    }

    @Test
    void testRepositoryStaticMethodWithSecurityAnnotation() {

    }

    @Test
    void testRepositoryDefaultMethodWithSecurityAnnotation() {

    }

    @Test
    void testRepositoryParentMethodsSecured() {
        // here interface with @Repository annotation extends another interface with security annotations
        // TODO: this might not work!
        // TODO: or document this as not expected to work!!!!!!!!
    }

    private static void deleteEntityByName(String entityName) {
        // this doesn't check response status because if some assertion failed
        // could be legal that the entity doesn't exist, yet we want to clean-up
        // so that each test method is more likely to be isolated
        given()
                .pathParam("name", entityName)
                .contentType(ContentType.JSON)
                .when().delete("/by/name/{name}");
    }

    private static ValidatableResponse findEntityByName(String entityName) {
        return given()
                .pathParam("name", entityName)
                .contentType(ContentType.JSON)
                .when().get("/by/name/{name}")
                .then();
    }

    private static void createEntityPublic(String entityName) {
        given()
                .body(new MyEntity(entityName))
                .contentType(ContentType.JSON)
                .when().post("/insert-public")
                .then()
                .statusCode(204);
    }
}
