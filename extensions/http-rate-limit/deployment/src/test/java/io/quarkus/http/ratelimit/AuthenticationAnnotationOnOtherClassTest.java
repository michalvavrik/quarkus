package io.quarkus.http.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URL;
import java.util.List;
import java.util.Map;

import jakarta.inject.Inject;

import org.jboss.jandex.DotName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.builder.Version;
import io.quarkus.maven.dependency.Dependency;
import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.vertx.http.deployment.HttpAuthMechanismAnnotationBuildItem;
import io.quarkus.vertx.http.runtime.security.annotation.HttpAuthenticationMechanism;
import io.vertx.core.Vertx;

/**
 * An extension can accept its authentication annotation on classes that are not endpoints. For example, OIDC applies a
 * request filter annotated with {@code @BearerTokenAuthentication} to that mechanism only. Such a class selects the
 * authentication mechanism of no request, so the application can still have a post-authentication rule.
 */
public class AuthenticationAnnotationOnOtherClassTest {

    private static final String PREFIX = "quarkus.http.rate-limit.rules.api.";

    @RegisterExtension
    static final QuarkusExtensionTest config = TestHttp.withUsers(new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClasses(TestHttp.class, TestClient.class, TestHttp.Resource.class,
                    TokenAuthentication.class, TokenFilter.class, AnnotatedTokenFilter.class)))
            // what an extension does for its annotation, and for the interface that is not an endpoint
            .addBuildChainCustomizer(builder -> builder
                    .addBuildStep(context -> context.produce(new HttpAuthMechanismAnnotationBuildItem(
                            DotName.createSimple(TokenAuthentication.class), "token",
                            DotName.createSimple(TokenFilter.class))))
                    .produces(HttpAuthMechanismAnnotationBuildItem.class).build())
            .overrideConfigKey("quarkus.vertx.event-loops-pool-size", "1")
            .overrideConfigKey("quarkus.http.auth.proactive", "false")
            .overrideConfigKey(PREFIX + "paths", "/api/*")
            .overrideConfigKey(PREFIX + "phase", "post-authentication")
            .overrideConfigKey(PREFIX + "request-key", "principal")
            .overrideRuntimeConfigKey(PREFIX + "permits", "1")
            .overrideRuntimeConfigKey(PREFIX + "window", "1m")
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
    void postAuthenticationRuleLimitsPerPrincipal() {
        Map<String, String> alice = TestHttp.basic("alice", "alice");
        assertThat(http.get("/api/x", alice).statusCode()).isEqualTo(200);
        assertThat(http.get("/api/x", alice).statusCode()).isEqualTo(429);
        assertThat(http.get("/api/x", TestHttp.basic("bob", "bob")).statusCode()).isEqualTo(200);
    }

    @HttpAuthenticationMechanism("token")
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE, ElementType.METHOD })
    public @interface TokenAuthentication {
    }

    public interface TokenFilter {

        void filter();
    }

    @TokenAuthentication
    public static class AnnotatedTokenFilter implements TokenFilter {

        @Override
        public void filter() {
        }
    }
}
