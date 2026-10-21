package io.quarkus.oidc.test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TenantConfigResolver;
import io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType;
import io.quarkus.oidc.runtime.OidcTenantConfig.Provider;
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.quarkus.security.Authenticated;
import io.quarkus.test.QuarkusExtensionTest;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class DynamicTenantWithProviderTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClasses(GitHubResource.class, GitHubTenantConfigResolver.class))
            .withConfiguration("""
                    quarkus.keycloak.devservices.enabled=false
                    """);

    @Inject
    TenantConfigBean tenantConfigBean;

    @Test
    void testDynamicTenantConfigMergedWithProvider() {
        // the auth server URL and the web-app application type come from the GitHub provider config
        given().redirects().follow(false)
                .get("/github")
                .then()
                .statusCode(302)
                .header("location", startsWith("https://github.com/login/oauth/authorize"));
        var tenantContext = tenantConfigBean.getDynamicTenant("github");
        assertNotNull(tenantContext);
        var tenantConfig = tenantContext.getOidcTenantConfig();
        assertEquals(ApplicationType.WEB_APP, tenantConfig.applicationType().orElse(null));
        assertEquals("https://github.com/login/oauth", tenantConfig.authServerUrl().orElse(null));
        assertEquals("client", tenantConfig.clientId().orElse(null));
    }

    @Path("/github")
    public static class GitHubResource {

        @Authenticated
        @GET
        public String get() {
            return "github";
        }
    }

    @ApplicationScoped
    public static class GitHubTenantConfigResolver implements TenantConfigResolver {

        private final OidcTenantConfig config = OidcTenantConfig.builder()
                .tenantId("github")
                .provider(Provider.GITHUB)
                .clientId("client")
                .credentials("secret")
                .build();

        @Override
        public Uni<OidcTenantConfig> resolve(RoutingContext routingContext,
                OidcRequestContext<OidcTenantConfig> requestContext) {
            return Uni.createFrom().item(config);
        }
    }
}
