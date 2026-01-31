package io.quarkus.resteasy.reactive.server.test.security;

import static org.hamcrest.Matchers.is;

import java.io.File;
import java.net.URL;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.test.utils.TestIdentityController;
import io.quarkus.security.test.utils.TestIdentityProvider;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.vertx.http.runtime.security.annotation.BasicAuthentication;
import io.quarkus.vertx.http.runtime.security.annotation.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.annotation.MTLSAuthentication;
import io.restassured.RestAssured;

public class MtlsBasicAnnotationBasedAuthMechSelectionTest {

    @TestHTTPResource(value = "/mtls", tls = true)
    URL mtlsUrl;

    @TestHTTPResource(value = "/basic", tls = true)
    URL basicUrl;

    @TestHTTPResource(value = "/basic-or-mtls", tls = true)
    URL basicOrMtlsUrl;

    @TestHTTPResource(value = "/class-level/mtls", tls = true)
    URL overrideClassLevelMtlsUrl;

    @TestHTTPResource(value = "/class-level/basic", tls = true)
    URL overrideClassLevelBasicUrl;

    @TestHTTPResource(value = "/class-level/custom", tls = true)
    URL overrideClassLevelCustomUrl;

    @TestHTTPResource(value = "/class-level/custom-repeated", tls = true)
    URL overrideClassLevelCustomRepeatedUrl;

    @TestHTTPResource(value = "/custom-repeated", tls = true)
    URL customRepeatedUrl;

    @TestHTTPResource(value = "/class-level/basic-or-mtls", tls = true)
    URL classLevelBasicOrMtlsUrl;

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(MethodLevelSecurityResource.class, CustomHeaderAuthenticateMechanism.class,
                            ClassLevelSecurityResource.class)
                    .addClasses(TestIdentityProvider.class, TestTrustedIdentityProvider.class, TestIdentityController.class)
                    .addAsResource("mtls/mtls-basic-jks.conf", "application.properties")
                    .addAsResource("mtls/server-keystore.jks", "server-keystore.jks")
                    .addAsResource("mtls/server-truststore.jks", "server-truststore.jks"));

    @BeforeAll
    public static void setup() {
        TestIdentityController.resetRoles()
                .add("admin", "admin", "admin");
    }

    @Test
    public void testOtherMechanismNotAllowed() {
        // MTLS select, don't allow anything else
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .header("custom-auth", "ignored")
                .get(mtlsUrl).then().statusCode(401);
        // Basic selected, don't allow anything else
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .header("custom-auth", "ignored")
                .get(basicUrl).then().statusCode(401);
        // Basic or Mutual TLS selected, don't allow anything else
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .header("custom-auth", "ignored")
                .get(basicOrMtlsUrl).then().statusCode(401);
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .header("custom-auth", "ignored")
                .get(classLevelBasicOrMtlsUrl).then().statusCode(401);
    }

    @Test
    public void testMethodLevelMutualTlsOrBasicAuthenticationEnforced() {
        // anonymous user must not be allowed as we used an annotation selecting authentication mechanism
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(basicOrMtlsUrl).then().statusCode(401);
        // endpoint is annotated with @MTLSAuthentication, therefore mTLS must pass
        RestAssured.given()
                .keyStore(new File("src/test/resources/mtls/client-keystore.jks"), "password")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(basicOrMtlsUrl).then().statusCode(200).body(is("CN=client,OU=cert,O=quarkus,L=city,ST=state,C=AU"));
        // endpoint is annotated with @BasicAuthentication, therefore basic must pass
        RestAssured.given()
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(basicOrMtlsUrl).then().statusCode(200).body(is("admin"));
    }

    @Test
    public void testClassLevelMutualTlsOrBasicAuthenticationEnforced() {
        // anonymous user must not be allowed as we used an annotation selecting authentication mechanism
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(classLevelBasicOrMtlsUrl).then().statusCode(401);
        // resource is annotated with @MTLSAuthentication, therefore mTLS must pass
        RestAssured.given()
                .keyStore(new File("src/test/resources/mtls/client-keystore.jks"), "password")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(classLevelBasicOrMtlsUrl).then().statusCode(200)
                .body(is("CN=client,OU=cert,O=quarkus,L=city,ST=state,C=AU"));
        // resource is annotated with @BasicAuthentication, therefore basic must pass
        RestAssured.given()
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(classLevelBasicOrMtlsUrl).then().statusCode(200).body(is("admin"));
    }

    @Test
    public void testMutualTLSAuthenticationEnforced() {
        // endpoint is annotated with @MTLS, therefore mTLS must pass while anything less fail
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(mtlsUrl).then().statusCode(401);
        RestAssured.given()
                .keyStore(new File("src/test/resources/mtls/client-keystore.jks"), "password")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(mtlsUrl).then().statusCode(200).body(is("CN=client,OU=cert,O=quarkus,L=city,ST=state,C=AU"));
        RestAssured.given()
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(mtlsUrl).then().statusCode(401);
        // same expectations for the method-level annotation overriding the class-level annotation
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelMtlsUrl).then().statusCode(401);
        RestAssured.given()
                .keyStore(new File("src/test/resources/mtls/client-keystore.jks"), "password")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelMtlsUrl).then().statusCode(200)
                .body(is("CN=client,OU=cert,O=quarkus,L=city,ST=state,C=AU"));
        RestAssured.given()
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelMtlsUrl).then().statusCode(401);
    }

    @Test
    public void testBasicAuthenticationEnforced() {
        // endpoint is annotated with @Basic, therefore basic auth must pass while anything less fail
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(basicUrl).then().statusCode(401);
        RestAssured.given()
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(basicUrl).then().statusCode(200).body(is("admin"));
        RestAssured.given()
                .keyStore(new File("src/test/resources/mtls/client-keystore.jks"), "password")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(basicUrl).then().statusCode(401);
        // same expectations for the method-level annotation overriding the class-level annotation
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelBasicUrl).then().statusCode(401);
        RestAssured.given()
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelBasicUrl).then().statusCode(200).body(is("admin"));
        RestAssured.given()
                .keyStore(new File("src/test/resources/mtls/client-keystore.jks"), "password")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelBasicUrl).then().statusCode(401);
    }

    @Test
    public void testCustomAuthenticationMechanismEnforced() {
        // anonymous not allowed
        RestAssured.given()
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelCustomUrl).then().statusCode(401);
        // basic not allowed
        RestAssured.given()
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelCustomUrl).then().statusCode(401);
        // mTLS not allowed
        RestAssured.given()
                .keyStore(new File("src/test/resources/mtls/client-keystore.jks"), "password")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelCustomUrl).then().statusCode(401);
        // custom allowed
        RestAssured.given()
                .header("custom-auth", "ignored")
                .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                .get(overrideClassLevelCustomUrl).then().statusCode(200).body(is("donald"));
    }

    @Test
    public void testRepeatedCustomAuthenticationMechanismEnforced() {
        URL[] urls = { overrideClassLevelCustomRepeatedUrl, customRepeatedUrl };
        for (URL url : urls) {
            // anonymous not allowed
            RestAssured.given()
                    .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                    .get(url).then().statusCode(401);
            // basic not allowed
            RestAssured.given()
                    .auth()
                    .preemptive()
                    .basic("admin", "admin")
                    .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                    .get(url).then().statusCode(401);
            // mTLS not allowed
            RestAssured.given()
                    .keyStore(new File("src/test/resources/mtls/client-keystore.jks"), "password")
                    .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                    .get(url).then().statusCode(401);
            // 'custom-head-mech' not allowed
            RestAssured.given()
                    .header("custom-auth", "ignored")
                    .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                    .get(url).then().statusCode(401);
            // 'custom-head-mech-1' allowed
            RestAssured.given()
                    .header("custom-auth", "ignored")
                    .header("custom-auth-postfix", "1")
                    .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                    .get(url).then().statusCode(200).body(is("donald"));
            // 'custom-head-mech-2' allowed
            RestAssured.given()
                    .header("custom-auth", "ignored")
                    .header("custom-auth-postfix", "2")
                    .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                    .get(url).then().statusCode(200).body(is("donald"));
            // 'custom-head-mech-3' not allowed
            RestAssured.given()
                    .header("custom-auth", "ignored")
                    .header("custom-auth-postfix", "3")
                    .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                    .get(url).then().statusCode(401);
            // 'custom-head-mech-4' allowed
            RestAssured.given()
                    .header("custom-auth", "ignored")
                    .header("custom-auth-postfix", "4")
                    .trustStore(new File("src/test/resources/mtls/client-truststore.jks"), "password")
                    .get(url).then().statusCode(200).body(is("donald"));
        }
    }

    @Path("/")
    public static class MethodLevelSecurityResource {

        @Inject
        SecurityIdentity identity;

        @MTLSAuthentication
        @Path("mtls")
        @GET
        public String mtls() {
            return identity.getPrincipal().getName();
        }

        @BasicAuthentication
        @Path("basic")
        @GET
        public String basic() {
            return identity.getPrincipal().getName();
        }

        @MTLSAuthentication
        @BasicAuthentication
        @Path("basic-or-mtls")
        @GET
        public String basicOrMtls() {
            return identity.getPrincipal().getName();
        }

        @HttpAuthenticationMechanism("custom-head-mech-1")
        @HttpAuthenticationMechanism("custom-head-mech-2")
        @HttpAuthenticationMechanism("custom-head-mech-4")
        @Path("custom-repeated")
        @GET
        public String customRepeated() {
            return identity.getPrincipal().getName();
        }

    }

    @MTLSAuthentication
    @BasicAuthentication
    @Path("/class-level")
    public static class ClassLevelSecurityResource {

        @Inject
        SecurityIdentity identity;

        @MTLSAuthentication
        @Path("mtls")
        @GET
        public String mtls() {
            return identity.getPrincipal().getName();
        }

        @BasicAuthentication
        @Path("basic")
        @GET
        public String basic() {
            return identity.getPrincipal().getName();
        }

        @HttpAuthenticationMechanism("custom-head-mech")
        @Path("custom")
        @GET
        public String custom() {
            return identity.getPrincipal().getName();
        }

        @HttpAuthenticationMechanism("custom-head-mech-1")
        @HttpAuthenticationMechanism("custom-head-mech-2")
        @HttpAuthenticationMechanism("custom-head-mech-4")
        @Path("custom-repeated")
        @GET
        public String customRepeated() {
            return identity.getPrincipal().getName();
        }

        @Path("basic-or-mtls")
        @GET
        public String basicOrMtls() {
            return identity.getPrincipal().getName();
        }

    }
}
