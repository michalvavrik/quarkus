package io.quarkus.http.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.builder.Version;
import io.quarkus.maven.dependency.Dependency;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.annotation.BasicAuthentication;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.HttpResponse;

/**
 * A pre-authentication rule authenticates nothing, so it can limit an endpoint whose mechanism is selected by an
 * annotation: the endpoint is still authenticated with that mechanism, even when another one, tried first, accepts the
 * request too.
 */
public class AuthenticationAnnotationPreAuthenticationTest {

    @RegisterExtension
    static final QuarkusExtensionTest config = TestHttp.ipRule(TestHttp.withUsers(new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClasses(TestHttp.class, TestClient.class, AdminResource.class,
                    HeaderMechanism.class))),
            "admin", "/admin/*", 2, "1m")
            .overrideConfigKey("quarkus.vertx.event-loops-pool-size", "1")
            // required by the annotation
            .overrideConfigKey("quarkus.http.auth.proactive", "false")
            .setForcedDependencies(List.of(
                    Dependency.of("io.quarkus", "quarkus-elytron-security-properties-file-deployment", Version.getVersion())));

    @Inject
    Vertx vertx;

    @TestHTTPResource
    URL url;

    TestClient http;

    @BeforeEach
    void createClient() {
        http = new TestClient(vertx, url);
    }

    @AfterEach
    void closeClient() {
        http.close();
    }

    @Test
    void annotationSelectsTheMechanismOfALimitedEndpoint() {
        Map<String, String> aliceAndBob = new HashMap<>(TestHttp.basic("alice", "alice"));
        aliceAndBob.put("X-User", "bob");
        HttpResponse<Buffer> served = http.get("/admin", aliceAndBob);
        assertThat(served.statusCode()).isEqualTo(200);
        assertThat(served.bodyAsString()).isEqualTo("alice");

        // the challenge of the selected mechanism; a request that fails authentication spends a permit too
        HttpResponse<Buffer> challenged = http.get("/admin");
        assertThat(challenged.statusCode()).isEqualTo(401);
        assertThat(challenged.getHeader("WWW-Authenticate")).startsWithIgnoringCase("basic");

        assertThat(http.get("/admin", aliceAndBob).statusCode()).isEqualTo(429);
    }

    @Path("/admin")
    public static class AdminResource {

        @Inject
        SecurityIdentity identity;

        @GET
        @BasicAuthentication
        public String user() {
            return identity.getPrincipal().getName();
        }
    }

    /**
     * Trusts the user named by the {@code X-User} header, and is tried before basic authentication.
     */
    @ApplicationScoped
    public static class HeaderMechanism implements HttpAuthenticationMechanism {

        @Override
        public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
            String user = context.request().getHeader("X-User");
            if (user == null) {
                return Uni.createFrom().nullItem();
            }
            return identityProviderManager.authenticate(new TrustedAuthenticationRequest(user));
        }

        @Override
        public Uni<ChallengeData> getChallenge(RoutingContext context) {
            return Uni.createFrom().item(new ChallengeData(401, "WWW-Authenticate", "x-user"));
        }

        @Override
        public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
            return Set.of(TrustedAuthenticationRequest.class);
        }

        @Override
        public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
            return Uni.createFrom()
                    .item(new HttpCredentialTransport(HttpCredentialTransport.Type.OTHER_HEADER, "X-User", "x-user"));
        }

        @Override
        public int getPriority() {
            return 5000;
        }
    }
}
