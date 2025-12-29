package io.quarkus.websockets.next.test.security;

import static io.quarkus.websockets.next.test.security.SecurityTestBase.basicAuth;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.concurrent.CompletionException;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.runtime.util.ExceptionUtil;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.test.utils.TestIdentityController;
import io.quarkus.security.test.utils.TestIdentityProvider;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.quarkus.vertx.http.security.AuthorizationPolicy;
import io.quarkus.websockets.next.OnTextMessage;
import io.quarkus.websockets.next.WebSocket;
import io.quarkus.websockets.next.test.utils.WSClient;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Vertx;
import io.vertx.core.http.UpgradeRejectedException;
import io.vertx.ext.web.RoutingContext;

class HttpUpgradeAuthorizationPolicyAnnotationTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot(root -> root.addClasses(
            Endpoint.class, TestIdentityProvider.class, TestIdentityController.class, WSClient.class,
            TrustMeHttpSecurityPolicy.class, SecurityTestBase.class));

    @Inject
    Vertx vertx;

    @TestHTTPResource("end")
    URI endUri;

    @BeforeAll
    static void setupUsers() {
        TestIdentityController.resetRoles().add("admin", "admin", "admin");
    }

    @Test
    void testNonBlockingSimplePolicyApplied() {
        try (WSClient client = new WSClient(vertx)) {
            CompletionException ce = assertThrows(CompletionException.class, () -> client.connect(endUri));
            Throwable root = ExceptionUtil.getRootCause(ce);
            assertInstanceOf(UpgradeRejectedException.class, root);
            assertTrue(root.getMessage().contains("401"),
                    () -> "Expected message to contain response status 401, but got: " + root.getMessage());
        }
        try (WSClient client = new WSClient(vertx)) {
            CompletionException ce = assertThrows(CompletionException.class,
                    () -> client.connect(basicAuth("admin", "admin"), endUri));
            Throwable root = ExceptionUtil.getRootCause(ce);
            assertInstanceOf(UpgradeRejectedException.class, root);
            assertTrue(root.getMessage().contains("403"),
                    () -> "Expected message to contain response status 401, but got: " + root.getMessage());
        }
    }

    @AuthorizationPolicy(name = "TrustMe")
    @WebSocket(path = "/end")
    static class Endpoint {

        @OnTextMessage
        String echo(String message) {
            return message;
        }

    }

    @ApplicationScoped
    static class TrustMeHttpSecurityPolicy implements HttpSecurityPolicy {

        @Override
        public Uni<CheckResult> checkPermission(RoutingContext routingContext, Uni<SecurityIdentity> identity,
                AuthorizationRequestContext requestContext) {
            if (customRequestAuthorization(routingContext)) {
                return CheckResult.permit();
            }
            return CheckResult.deny();
        }

        @Override
        public String name() {
            return "TrustMe";
        }

        private static boolean customRequestAuthorization(RoutingContext routingContext) {
            // here comes your custom authorization check
            // for example, you can check headers:
            String authorization = routingContext.request().getHeader("CustomAuthorization");
            return verifyAuthorization(authorization);
        }

        private static boolean verifyAuthorization(String authorization) {
            return "TrustMe".equals(authorization);
        }
    }
}
