package io.quarkus.oidc;

public interface OidcTenantConfig extends io.quarkus.oidc.runtime.OidcTenantConfig {

    /**
     * Creates {@link OidcTenantConfigBuilder} builder populated with documented default values.
     *
     * @return OidcTenantConfigBuilder builder
     */
    static OidcTenantConfigBuilder builder() {
        return new OidcTenantConfigBuilder();
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder from the existing {@link io.quarkus.oidc.runtime.OidcTenantConfig}
     *
     * @param mapping existing io.quarkus.oidc.runtime.OidcTenantConfig
     */
    static OidcTenantConfigBuilder builder(io.quarkus.oidc.runtime.OidcTenantConfig mapping) {
        return new OidcTenantConfigBuilder(mapping);
    }

    /**
     * Creates {@link OidcTenantConfig} from the {@code mapping}. This method is more efficient than
     * the {@link #builder()} method if you don't need to modify the {@code mapping}.
     *
     * @param mapping existing io.quarkus.oidc.runtime.OidcTenantConfig
     * @return OidcTenantConfig
     */
    static OidcTenantConfig of(io.quarkus.oidc.runtime.OidcTenantConfig mapping) {
        if (mapping instanceof OidcTenantConfig oidcTenantConfig) {
            return oidcTenantConfig;
        }
        return builder(mapping).build();
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder populated with documented default values and the provided base URL.
     *
     * @param authServerUrl {@link #authServerUrl()}
     * @return OidcTenantConfigBuilder builder
     */
    static OidcTenantConfigBuilder authServerUrl(String authServerUrl) {
        return builder().authServerUrl(authServerUrl);
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder populated with documented default values and the provided client
     * registration path.
     *
     * @param registrationPath {@link #registrationPath()}
     * @return OidcTenantConfigBuilder builder
     */
    static OidcTenantConfigBuilder registrationPath(String registrationPath) {
        return builder().registrationPath(registrationPath);
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder populated with documented default values and the provided token path.
     *
     * @param tokenPath {@link #tokenPath()}
     * @return OidcTenantConfigBuilder builder
     */
    static OidcTenantConfigBuilder tokenPath(String tokenPath) {
        return builder().tokenPath(tokenPath);
    }

}
