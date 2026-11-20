package io.quarkus.http.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.builder.Version;
import io.quarkus.maven.dependency.Dependency;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.test.QuarkusExtensionTest;
import io.quarkus.vertx.http.runtime.security.annotation.BasicAuthentication;

/**
 * An annotation such as {@code @BasicAuthentication} selects the mechanism that authenticates the requests of an
 * endpoint, once the endpoint is known. A post-authentication rule authenticates a request before that, with whichever
 * mechanism accepts it, so an application cannot have both. The build does not know the paths of an endpoint: it fails
 * even when, as here, the rule and the annotated endpoint have different paths.
 */
public class AuthenticationAnnotationFailsBuildTest {

    private static final String PREFIX = "quarkus.http.rate-limit.rules.api.";

    @RegisterExtension
    static final QuarkusExtensionTest config = TestHttp.withUsers(new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClasses(TestHttp.class, AdminResource.class)))
            // required by the annotation
            .overrideConfigKey("quarkus.http.auth.proactive", "false")
            .overrideConfigKey(PREFIX + "paths", "/api/*")
            .overrideConfigKey(PREFIX + "phase", "post-authentication")
            .overrideConfigKey(PREFIX + "request-key", "principal")
            .overrideRuntimeConfigKey(PREFIX + "permits", "1")
            .overrideRuntimeConfigKey(PREFIX + "window", "1m")
            .setForcedDependencies(List.of(
                    Dependency.of("io.quarkus", "quarkus-elytron-security-properties-file-deployment", Version.getVersion())))
            .assertException(t -> assertThat(t).rootCause().isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("Rate limit rule 'api' has phase=post-authentication, which cannot be used in an"
                            + " application that selects how a request is authenticated with annotations such as"
                            + " @BasicAuthentication or @Tenant (found on " + AdminResource.class.getName()
                            + "#list): the rule authenticates a request before its endpoint, and with it the annotation,"
                            + " is known. Use phase=pre-authentication, or select the mechanism or tenant by path"
                            + " instead"));

    @Test
    void buildFails() {
        // the extension asserts the build failure
    }

    @Path("/admin")
    public static class AdminResource {

        @GET
        @BasicAuthentication
        public String list() {
            return "admin";
        }
    }
}
