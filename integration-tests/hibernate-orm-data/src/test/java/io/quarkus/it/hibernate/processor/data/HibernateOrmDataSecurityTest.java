package io.quarkus.it.hibernate.processor.data;

import static io.restassured.RestAssured.given;

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

    @TestSecurity(user = "hudson", roles = "admin")
    @TestHTTPEndpoint(SecuredMyEntityResource.class)
    @Test
    void testMethodLevelRolesAllowed() {
        // this Jakarta Data repository requires "root" role, but we have "admin"
        given()
                .body(new MyEntity("foo"))
                .contentType(ContentType.JSON)
                .when().post("/insert-root")
                .then()
                .statusCode(403);
        testMethodLevelPermitAllByRetrievingEntity("foo").statusCode(404);

        // this Jakarta Data repository requires "admin" role and we have it
        given()
                .body(new MyEntity("foo"))
                .contentType(ContentType.JSON)
                .when().post("/insert-admin")
                .then()
                .statusCode(204);
        testMethodLevelPermitAllByRetrievingEntity("foo").statusCode(200);

        // clean-up
        testMethodLevelPermitAllByDeletingEntity("foo");
    }

    @Test
    void testMethodLevelRolesAllowedPropertyExpansion() {
        // TODO: what if the method is present on multiple interfaces with the same signature
    }

    @Test
    void testMethodLevelSinglePermissionsAllowed() {
        // TODO: test overloaded methods
    }

    @Test
    void testMethodLevelMultiplePermissionsAllowed() {

    }

    @Test
    void testMethodLevelPermissionsAllowedMetaAnnotation() {

    }

    @Test
    void testMethodLevelAuthorizationPolicy() {

    }

    @Test
    void testMethodLevelDenyAll() {

    }

    @Test
    void testMethodLevelAuthenticated() {

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
    void testClassLevelAuthorizationPolicy() {

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
    }

    @Test
    void testUnsecuredMethodsArePublic() {
        // call repository methods not annotated with security annotations in repository
        // where other methods are secured and expect the unannotated methods are not secured

    }

    private void testMethodLevelPermitAllByDeletingEntity(String entityName) {
        given()
                .pathParam("name", entityName)
                .contentType(ContentType.JSON)
                .when().delete("/by/name/{name}")
                .then()
                .statusCode(204);
        testMethodLevelPermitAllByRetrievingEntity(entityName).statusCode(404);
    }

    private ValidatableResponse testMethodLevelPermitAllByRetrievingEntity(String entityName) {
        return given()
                .pathParam("name", entityName)
                .contentType(ContentType.JSON)
                .when().get("/by/name/{name}")
                .then();
    }
}
