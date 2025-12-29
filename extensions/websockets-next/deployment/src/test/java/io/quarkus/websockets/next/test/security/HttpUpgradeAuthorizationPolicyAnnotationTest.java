package io.quarkus.websockets.next.test.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.concurrent.CompletionException;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.runtime.util.ExceptionUtil;
import io.quarkus.security.PermissionChecker;
import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
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
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.UpgradeRejectedException;
import io.vertx.core.http.WebSocketConnectOptions;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.web.RoutingContext;

class HttpUpgradeAuthorizationPolicyAnnotationTest {

    private static final String CUSTOM_AUTHORIZATION = "CustomAuthorization";

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot(root -> root.addClasses(
            TrustMeEndpoint.class, TestIdentityProvider.class, TestIdentityController.class, WSClient.class,
            HeaderHttpSecurityPolicy.class, PolicyProducer.class, BlockMeEndpoint.class, AugmentMeEndpoint.class,
            PublicEndpoint.class, TwiceSecuredEndpoint.class));

    @Inject
    Vertx vertx;

    @TestHTTPResource("trust-me-endpoint")
    URI trustMeUri;

    @TestHTTPResource("block-me-endpoint")
    URI blockMeUri;

    @TestHTTPResource("augment-me-endpoint")
    URI augmentMeUri;

    @TestHTTPResource("public-endpoint")
    URI publicUri;

    @TestHTTPResource("twice-secured-endpoint")
    URI twiceSecuredUri;

    @BeforeAll
    static void setupUsers() {
        TestIdentityController.resetRoles().add("admin", "admin", "admin");
    }

    @Test
    void testNonBlockingAuthorizationPolicy() {
        testEchoEndpoint(trustMeUri, "TrustMe");
    }

    @Test
    void testBlockingAuthorizationPolicy() {
        testEchoEndpoint(blockMeUri, "BlockMe");
    }

    @Test
    void testIdentityAugmentationByAuthorizationPolicy() {
        testEchoEndpoint(augmentMeUri, "AugmentMe");
        // FIXME: security events
    }

    @Test
    void testPolicyNotAppliedOnUnsecuredEndpoint() {
        try (WSClient client = new WSClient(vertx)) {
            client.connect(publicUri);
            client.sendAndAwait("hello");
            client.waitForMessages(1);
            assertEquals("hello", client.getMessages().get(0).toString());
        }
    }

    @Test
    void testPolicySecurityUpgradeAndPermissionsSecuringPayload() {
        testEchoEndpoint(twiceSecuredUri, "TwiceSecured");
    }

    private void testEchoEndpoint(URI uri, String headerValue) {
        try (WSClient client = new WSClient(vertx)) {
            CompletionException ce = assertThrows(CompletionException.class, () -> client.connect(uri));
            Throwable root = ExceptionUtil.getRootCause(ce);
            assertInstanceOf(UpgradeRejectedException.class, root);
            assertTrue(root.getMessage().contains("401"),
                    () -> "Expected message to contain response status 401, but got: " + root.getMessage());
        }
        try (WSClient client = new WSClient(vertx)) {
            CompletionException ce = assertThrows(CompletionException.class,
                    () -> client.connect(basicAuth("admin", "admin"), uri));
            Throwable root = ExceptionUtil.getRootCause(ce);
            assertInstanceOf(UpgradeRejectedException.class, root);
            assertTrue(root.getMessage().contains("403"),
                    () -> "Expected message to contain response status 401, but got: " + root.getMessage());
        }
        try (WSClient client = new WSClient(vertx)) {
            client.connect(basicAuth("admin", "admin").addHeader(CUSTOM_AUTHORIZATION, headerValue), uri);
            client.sendAndAwait("hello");
            client.waitForMessages(1);
            assertEquals("hello", client.getMessages().get(0).toString());
        }
    }

    private static WebSocketConnectOptions basicAuth(String username, String password) {
        return new WebSocketConnectOptions().addHeader(HttpHeaders.AUTHORIZATION.toString(),
                new UsernamePasswordCredentials(username, password).applyHttpChallenge(null).toHttpAuthorization());
    }

    @WebSocket(path = "/public-endpoint")
    static class PublicEndpoint {

        @OnTextMessage
        String echo(String message) {
            return message;
        }

    }

    @AuthorizationPolicy(name = "TwiceSecured")
    @WebSocket(path = "/twice-secured-endpoint")
    static class TwiceSecuredEndpoint {

        @PermissionsAllowed("hello")
        @OnTextMessage
        String echo(String message) {
            return message;
        }
    }

    @AuthorizationPolicy(name = "TrustMe")
    @WebSocket(path = "/trust-me-endpoint")
    static class TrustMeEndpoint {

        @OnTextMessage
        String echo(String message) {
            return message;
        }

    }

    @AuthorizationPolicy(name = "BlockMe")
    @WebSocket(path = "/block-me-endpoint")
    static class BlockMeEndpoint {

        @OnTextMessage
        String echo(String message) {
            return message;
        }

    }

    @AuthorizationPolicy(name = "AugmentMe")
    @WebSocket(path = "/augment-me-endpoint")
    static class AugmentMeEndpoint {

        @OnTextMessage
        String echo(String message) {
            return message;
        }

    }

    @Singleton
    static class PolicyProducer {

        @ApplicationScoped
        @Produces
        HttpSecurityPolicy trustedPolicy() {
            return new HeaderHttpSecurityPolicy("TrustMe");
        }

        @ApplicationScoped
        @Produces
        HttpSecurityPolicy twiceSecuredPolicy() {
            return new HeaderHttpSecurityPolicy("TwiceSecured");
        }

        @ApplicationScoped
        @Produces
        HttpSecurityPolicy augmentingPolicy() {
            return new HeaderHttpSecurityPolicy("AugmentMe") {
                @Override
                public Uni<CheckResult> checkPermission(RoutingContext routingContext, Uni<SecurityIdentity> identityUni,
                        AuthorizationRequestContext requestContext) {
                    return identityUni.map(identity -> {
                        SecurityIdentity augmentedIdentity = QuarkusSecurityIdentity.builder(identity)
                                .addAttribute("new-attribute", "some-value").build();
                        if (customRequestAuthorization(routingContext)) {
                            return new CheckResult(true, augmentedIdentity);
                        }
                        return new CheckResult(false, augmentedIdentity);
                    });
                }
            };
        }

        @ApplicationScoped
        @Produces
        HttpSecurityPolicy blockingPolicy() {
            return new HeaderHttpSecurityPolicy("BlockMe") {
                @Override
                public Uni<CheckResult> checkPermission(RoutingContext routingContext, Uni<SecurityIdentity> identityUni,
                        AuthorizationRequestContext requestContext) {
                    return requestContext.runBlocking(routingContext, identityUni, (rc, identity) -> {
                        if (identity.isAnonymous()) {
                            return CheckResult.DENY;
                        }
                        if (customRequestAuthorization(routingContext)) {
                            return CheckResult.PERMIT;
                        }
                        return CheckResult.DENY;
                    });
                }
            };
        }

        @PermissionChecker("hello")
        boolean isPayloadHello(String message) {
            return "hello".equals(message);
        }
    }

    static class HeaderHttpSecurityPolicy implements HttpSecurityPolicy {

        private final String name;

        HeaderHttpSecurityPolicy(String name) {
            this.name = name;
        }

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
            return name;
        }

        protected boolean customRequestAuthorization(RoutingContext routingContext) {
            String authorization = routingContext.request().getHeader(CUSTOM_AUTHORIZATION);
            return verifyAuthorization(authorization);
        }

        private boolean verifyAuthorization(String authorization) {
            return name.equals(authorization);
        }
    }
}
