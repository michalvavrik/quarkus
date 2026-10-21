package io.quarkus.oidc.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.oidc.runtime.OidcTenantConfig.Provider;

public class OidcImplTest {

    @Test
    public void testCreateServiceApp() {
        final OidcImpl oidc = new OidcImpl(getEmptyConfig());
        oidc.createServiceApp("auth-server-url-1");
        final OidcTenantConfig defaultTenantConfig = oidc.getDefaultTenantConfig();
        assertEquals("auth-server-url-1", defaultTenantConfig.authServerUrl().get());
        assertEquals(OidcTenantConfig.ApplicationType.SERVICE, defaultTenantConfig.applicationType().get());
    }

    @Test
    public void testCreateWebApp() {
        final OidcImpl oidc = new OidcImpl(getEmptyConfig());
        oidc.createWebApp("auth-server-url-1", "client5", "secret2");
        final OidcTenantConfig defaultTenantConfig = oidc.getDefaultTenantConfig();
        assertEquals("auth-server-url-1", defaultTenantConfig.authServerUrl().get());
        assertEquals(OidcTenantConfig.ApplicationType.WEB_APP, defaultTenantConfig.applicationType().get());
        assertEquals("client5", defaultTenantConfig.clientId().get());
        assertEquals("secret2", defaultTenantConfig.credentials().secret().get());
    }

    @Test
    public void testResolveProviderConfigs() {
        final OidcImpl oidc = new OidcImpl(getEmptyConfig());
        oidc.create(io.quarkus.oidc.OidcTenantConfig.builder().provider(Provider.GITHUB).clientId("client1").build());
        oidc.create(io.quarkus.oidc.OidcTenantConfig.authServerUrl("http://localhost/slack").tenantId("slack")
                .provider(Provider.SLACK).build());
        final var keycloakTenantConfig = io.quarkus.oidc.OidcTenantConfig.authServerUrl("http://localhost/keycloak")
                .tenantId("keycloak").build();
        oidc.create(keycloakTenantConfig);

        // tenant configs are not merged with well-known providers when they are created
        assertEquals(Provider.GITHUB, oidc.getDefaultTenantConfig().provider().orElse(null));
        assertTrue(oidc.getDefaultTenantConfig().authServerUrl().isEmpty());
        assertEquals(Provider.SLACK, oidc.getStaticTenantConfigs().get("slack").provider().orElse(null));
        assertTrue(oidc.getStaticTenantConfigs().get("slack").applicationType().isEmpty());

        oidc.resolveProviderConfigs();

        final OidcTenantConfig defaultTenantConfig = oidc.getDefaultTenantConfig();
        assertTrue(defaultTenantConfig.provider().isEmpty());
        assertEquals("https://github.com/login/oauth", defaultTenantConfig.authServerUrl().get());
        assertEquals(OidcTenantConfig.ApplicationType.WEB_APP, defaultTenantConfig.applicationType().get());
        assertEquals("client1", defaultTenantConfig.clientId().get());
        final OidcTenantConfig slackTenantConfig = oidc.getStaticTenantConfigs().get("slack");
        assertTrue(slackTenantConfig.provider().isEmpty());
        assertEquals("http://localhost/slack", slackTenantConfig.authServerUrl().get());
        assertEquals(OidcTenantConfig.ApplicationType.WEB_APP, slackTenantConfig.applicationType().get());
        assertSame(keycloakTenantConfig, oidc.getStaticTenantConfigs().get("keycloak"));
    }

    private static OidcConfig getEmptyConfig() {
        return new OidcConfig() {
            @Override
            public Map<String, OidcTenantConfig> namedTenants() {
                return Map.of(OidcConfig.DEFAULT_TENANT_KEY, io.quarkus.oidc.OidcTenantConfig.builder().build());
            }

            @Override
            public TokenCache tokenCache() {
                return null;
            }

            @Override
            public boolean resolveTenantsWithIssuer() {
                return false;
            }

            @Override
            public int priority() {
                return 0;
            }
        };
    }
}
