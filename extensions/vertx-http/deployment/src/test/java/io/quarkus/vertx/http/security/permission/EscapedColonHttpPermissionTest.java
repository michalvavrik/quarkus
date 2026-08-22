package io.quarkus.vertx.http.security.permission;

import java.util.function.Supplier;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.arc.Arc;
import io.quarkus.security.ForbiddenException;
import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.test.utils.TestIdentityController;
import io.quarkus.security.test.utils.TestIdentityProvider;
import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.restassured.RestAssured;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Handler;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

class EscapedColonHttpPermissionTest {

    private static final String EC = "\\:";

    @RegisterExtension
    static QuarkusExtensionTest test = new QuarkusExtensionTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClasses(TestIdentityController.class, TestIdentityProvider.class,
                            PermissionsPathHandler.class, CDIBean.class)
                    .addAsResource(new StringAsset("""
                            quarkus.http.auth.policy.t1.roles-allowed=test,admin
                            quarkus.http.auth.policy.t1.permissions.test=system\\:role\\:query1
                            quarkus.http.auth.permission.t1.paths=/test/escaped-name
                            quarkus.http.auth.permission.t1.policy=t1

                            quarkus.http.auth.policy.t2.roles-allowed=test,admin
                            quarkus.http.auth.policy.t2.permissions.test=system\\:role:query
                            quarkus.http.auth.permission.t2.paths=/test/escaped-name-with-action
                            quarkus.http.auth.permission.t2.policy=t2

                            quarkus.http.auth.policy.t3.roles-allowed=test,admin
                            quarkus.http.auth.policy.t3.permissions.test=perm:role\\:query
                            quarkus.http.auth.permission.t3.paths=/test/escaped-action
                            quarkus.http.auth.permission.t3.policy=t3

                            quarkus.http.auth.policy.t4.roles-allowed=test,admin
                            quarkus.http.auth.policy.t4.permissions.test=simple-perm:action1
                            quarkus.http.auth.permission.t4.paths=/test/plain
                            quarkus.http.auth.permission.t4.policy=t4

                            quarkus.http.auth.policy.t5.roles-allowed=test,admin
                            quarkus.http.auth.policy.t5.permissions.test=a\\:b\\:c\\:d
                            quarkus.http.auth.permission.t5.paths=/test/multi-escaped-name
                            quarkus.http.auth.permission.t5.policy=t5

                            quarkus.http.auth.policy.t6.roles-allowed=test,admin
                            quarkus.http.auth.policy.t6.permissions.test=perm:x\\:y\\:z
                            quarkus.http.auth.permission.t6.paths=/test/multi-escaped-action
                            quarkus.http.auth.permission.t6.policy=t6
                            """), "application.properties"));

    @Test
    void escapedColonsInPermissionName() {
        authenticateTest();
        RestAssured.given().auth().preemptive().basic("test", "test").get("/test/escaped-name")
                .then().statusCode(200).body(Matchers.is("test:/test/escaped-name"));

        authenticateAdmin();
        RestAssured.given().auth().preemptive().basic("admin", "admin").get("/test/escaped-name")
                .then().statusCode(403);

        RestAssured.given().get("/test/escaped-name").then().statusCode(401);
    }

    @Test
    void escapedColonInNameWithAction() {
        authenticateTest();
        RestAssured.given().auth().preemptive().basic("test", "test").get("/test/escaped-name-with-action")
                .then().statusCode(200).body(Matchers.is("test:/test/escaped-name-with-action"));

        authenticateAdmin();
        RestAssured.given().auth().preemptive().basic("admin", "admin").get("/test/escaped-name-with-action")
                .then().statusCode(403);
    }

    @Test
    void escapedColonInAction() {
        authenticateTest();
        RestAssured.given().auth().preemptive().basic("test", "test").get("/test/escaped-action")
                .then().statusCode(200).body(Matchers.is("test:/test/escaped-action"));

        authenticateAdmin();
        RestAssured.given().auth().preemptive().basic("admin", "admin").get("/test/escaped-action")
                .then().statusCode(403);
    }

    @Test
    void plainPermissionBackwardsCompat() {
        authenticateTest();
        RestAssured.given().auth().preemptive().basic("test", "test").get("/test/plain")
                .then().statusCode(200).body(Matchers.is("test:/test/plain"));

        authenticateAdmin();
        RestAssured.given().auth().preemptive().basic("admin", "admin").get("/test/plain")
                .then().statusCode(403);
    }

    @Test
    void multipleEscapedColonsInName() {
        authenticateTest();
        RestAssured.given().auth().preemptive().basic("test", "test").get("/test/multi-escaped-name")
                .then().statusCode(200).body(Matchers.is("test:/test/multi-escaped-name"));

        authenticateAdmin();
        RestAssured.given().auth().preemptive().basic("admin", "admin").get("/test/multi-escaped-name")
                .then().statusCode(403);
    }

    @Test
    void multipleEscapedColonsInAction() {
        authenticateTest();
        RestAssured.given().auth().preemptive().basic("test", "test").get("/test/multi-escaped-action")
                .then().statusCode(200).body(Matchers.is("test:/test/multi-escaped-action"));

        authenticateAdmin();
        RestAssured.given().auth().preemptive().basic("admin", "admin").get("/test/multi-escaped-action")
                .then().statusCode(403);
    }

    private void authenticateTest() {
        TestIdentityController.resetRoles().add("test", "test", "test");
    }

    private void authenticateAdmin() {
        TestIdentityController.resetRoles().add("admin", "admin", "admin");
    }

    @ApplicationScoped
    public static class PermissionsPathHandler {

        @Inject
        CDIBean cdiBean;

        public void setup(@Observes Router router) {
            router.route("/test/escaped-name").handler(new RouteHandler(cdiBean::escapedName));
            router.route("/test/escaped-name-with-action")
                    .handler(new RouteHandler(cdiBean::escapedNameWithAction));
            router.route("/test/escaped-action").handler(new RouteHandler(cdiBean::escapedAction));
            router.route("/test/plain").handler(new RouteHandler(cdiBean::plainPerm));
            router.route("/test/multi-escaped-name").handler(new RouteHandler(cdiBean::multiEscapedName));
            router.route("/test/multi-escaped-action").handler(new RouteHandler(cdiBean::multiEscapedAction));
        }
    }

    @ApplicationScoped
    public static class CDIBean {

        @PermissionsAllowed("system" + EC + "role" + EC + "query1")
        public Uni<Void> escapedName() {
            return Uni.createFrom().nullItem();
        }

        @PermissionsAllowed("system" + EC + "role:query")
        public Uni<Void> escapedNameWithAction() {
            return Uni.createFrom().nullItem();
        }

        @PermissionsAllowed("perm:role" + EC + "query")
        public Uni<Void> escapedAction() {
            return Uni.createFrom().nullItem();
        }

        @PermissionsAllowed("simple-perm:action1")
        public Uni<Void> plainPerm() {
            return Uni.createFrom().nullItem();
        }

        @PermissionsAllowed("a" + EC + "b" + EC + "c" + EC + "d")
        public Uni<Void> multiEscapedName() {
            return Uni.createFrom().nullItem();
        }

        @PermissionsAllowed("perm:x" + EC + "y" + EC + "z")
        public Uni<Void> multiEscapedAction() {
            return Uni.createFrom().nullItem();
        }
    }

    private static final class RouteHandler implements Handler<RoutingContext> {

        private final Supplier<Uni<Void>> callService;

        private RouteHandler(Supplier<Uni<Void>> callService) {
            this.callService = callService;
        }

        @Override
        public void handle(RoutingContext event) {
            Arc.container().requestContext().activate();
            QuarkusHttpUser user = (QuarkusHttpUser) event.user();
            Arc.container().instance(CurrentIdentityAssociation.class).get()
                    .setIdentity(user.getSecurityIdentity());
            callService.get().subscribe().with(unused -> {
                String ret = user.getSecurityIdentity().getPrincipal().getName()
                        + ":" + event.normalizedPath();
                event.response().end(ret);
            }, throwable -> {
                if (throwable instanceof UnauthorizedException) {
                    event.response().setStatusCode(401);
                } else if (throwable instanceof ForbiddenException) {
                    event.response().setStatusCode(403);
                } else {
                    event.response().setStatusCode(500);
                }
                event.end();
            });
        }
    }
}
