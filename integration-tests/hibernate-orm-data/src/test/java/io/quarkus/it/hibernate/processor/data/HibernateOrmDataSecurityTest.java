package io.quarkus.it.hibernate.processor.data;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

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

    @Test
    public void testMethodLevelRolesAllowed() {
        // TODO: test overloaded methods
    }

    @Test
    public void testMethodLevelRolesAllowedPropertyExpansion() {
        // TODO: what if the method is present on multiple interfaces with the same signature
    }

    @Test
    public void testMethodLevelSinglePermissionsAllowed() {

    }

    @Test
    public void testMethodLevelMultiplePermissionsAllowed() {

    }

    @Test
    public void testMethodLevelPermissionsAllowedMetaAnnotation() {

    }

    @Test
    public void testMethodLevelAuthorizationPolicy() {

    }

    @Test
    public void testMethodLevelPermitAll() {

    }

    @Test
    public void testMethodLevelDenyAll() {

    }

    @Test
    public void testMethodLevelAuthenticated() {

    }

    // FIXME: separator!!!!!!!!!!!!!!!!!!!!
    @Test
    public void testClassLevelRolesAllowed() {

    }

    @Test
    public void testClassLevelPermissionsAllowed() {

    }

    @Test
    public void testClassLevelPermissionsAllowedMetaAnnotation() {

    }

    @Test
    public void testClassLevelAuthorizationPolicy() {

    }

    @Test
    public void testClassLevelPermitAll() {

    }

    @Test
    public void testClassLevelDenyAll() {

    }

    @Test
    public void testClassLevelAuthenticated() {

    }

    @Test
    public void testRepositoryStaticMethodWithSecurityAnnotation() {

    }

    @Test
    public void testRepositoryDefaultMethodWithSecurityAnnotation() {

    }

    @Test
    public void testRepositoryParentMethodsSecured() {
        // here interface with @Repository annotation extends another interface with security annotations
        // TODO: this might not work!
    }

    @Test
    public void testUnsecuredMethodsArePublic() {
        // call repository methods not annotated with security annotations in repository
        // where other methods are secured and expect the unannotated methods are not secured

    }
}
