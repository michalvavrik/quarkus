package io.quarkus.oidc;

import java.util.List;
import java.util.Optional;

import io.quarkus.oidc.common.runtime.OidcClientCommonConfig;

public class OidcTenantConfig extends OidcClientCommonConfig implements io.quarkus.oidc.runtime.OidcTenantConfig {

    /**
     * Configuration this instance has been created from, it determines equality of tenant configurations.
     */
    private final io.quarkus.oidc.runtime.OidcTenantConfig mapping;

    /**
     * Authentication configuration with the UserInfo requirement set after this instance has been created.
     */
    private volatile io.quarkus.oidc.runtime.OidcTenantConfig.Authentication userInfoRequiredAuthentication;

    private OidcTenantConfig(io.quarkus.oidc.runtime.OidcTenantConfig mapping) {
        super(mapping);
        this.mapping = mapping;
    }

    @Override
    public Optional<String> tenantId() {
        return mapping.tenantId();
    }

    @Override
    public boolean tenantEnabled() {
        return mapping.tenantEnabled();
    }

    @Override
    public Optional<io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType> applicationType() {
        return mapping.applicationType();
    }

    @Override
    public Optional<String> authorizationPath() {
        return mapping.authorizationPath();
    }

    @Override
    public Optional<String> userInfoPath() {
        return mapping.userInfoPath();
    }

    @Override
    public Optional<String> introspectionPath() {
        return mapping.introspectionPath();
    }

    @Override
    public Optional<String> jwksPath() {
        return mapping.jwksPath();
    }

    @Override
    public Optional<String> endSessionPath() {
        return mapping.endSessionPath();
    }

    @Override
    public Optional<List<String>> tenantPaths() {
        return mapping.tenantPaths();
    }

    @Override
    public Optional<String> publicKey() {
        return mapping.publicKey();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.IntrospectionCredentials introspectionCredentials() {
        return mapping.introspectionCredentials();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.Roles roles() {
        return mapping.roles();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.Token token() {
        return mapping.token();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.Dpop dpop() {
        return mapping.dpop();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.Logout logout() {
        return mapping.logout();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.ResourceMetadata resourceMetadata() {
        return mapping.resourceMetadata();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.ClientIdMetadata clientIdMetadata() {
        return mapping.clientIdMetadata();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.CertificateChain certificateChain() {
        return mapping.certificateChain();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.Authentication authentication() {
        var authentication = userInfoRequiredAuthentication;
        return authentication == null ? mapping.authentication() : authentication;
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.CodeGrant codeGrant() {
        return mapping.codeGrant();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.TokenStateManager tokenStateManager() {
        return mapping.tokenStateManager();
    }

    @Override
    public boolean allowTokenIntrospectionCache() {
        return mapping.allowTokenIntrospectionCache();
    }

    @Override
    public boolean allowUserInfoCache() {
        return mapping.allowUserInfoCache();
    }

    @Override
    public Optional<Boolean> cacheUserInfoInIdtoken() {
        return mapping.cacheUserInfoInIdtoken();
    }

    @Override
    public io.quarkus.oidc.runtime.OidcTenantConfig.Jwks jwks() {
        return mapping.jwks();
    }

    @Override
    public Optional<io.quarkus.oidc.runtime.OidcTenantConfig.Provider> provider() {
        return mapping.provider();
    }

    /**
     * Sets the {@link io.quarkus.oidc.runtime.OidcTenantConfig.Authentication#userInfoRequired()} property after this
     * tenant configuration has been created, for example, because the OIDC provider metadata requires UserInfo.
     * This property is not compared by the {@link #equals(Object)} method.
     *
     * @param userInfoRequired {@link io.quarkus.oidc.runtime.OidcTenantConfig.Authentication#userInfoRequired()}
     */
    public void setUserInfoRequired(boolean userInfoRequired) {
        this.userInfoRequiredAuthentication = new OidcTenantConfigBuilder(mapping).authentication()
                .userInfoRequired(userInfoRequired).build();
    }

    /**
     * Tenant configurations are equal when the configurations they have been created from are equal.
     * Properties changed after the tenant configuration has been created are not compared.
     */
    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof OidcTenantConfig that && mapping.equals(that.mapping));
    }

    @Override
    public int hashCode() {
        return mapping.hashCode();
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder populated with documented default values.
     *
     * @return OidcTenantConfigBuilder builder
     */
    public static OidcTenantConfigBuilder builder() {
        return new OidcTenantConfigBuilder();
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder from the existing {@link io.quarkus.oidc.runtime.OidcTenantConfig}
     *
     * @param mapping existing io.quarkus.oidc.runtime.OidcTenantConfig
     */
    public static OidcTenantConfigBuilder builder(io.quarkus.oidc.runtime.OidcTenantConfig mapping) {
        return new OidcTenantConfigBuilder(mapping);
    }

    /**
     * Creates {@link OidcTenantConfig} from the {@code mapping}. This method is more efficient than
     * the {@link #builder()} method if you don't need to modify the {@code mapping}.
     *
     * @param mapping existing io.quarkus.oidc.runtime.OidcTenantConfig
     * @return OidcTenantConfig
     */
    public static OidcTenantConfig of(io.quarkus.oidc.runtime.OidcTenantConfig mapping) {
        return new OidcTenantConfig(mapping);
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder populated with documented default values and the provided base URL.
     *
     * @param authServerUrl {@link #authServerUrl()}
     * @return OidcTenantConfigBuilder builder
     */
    public static OidcTenantConfigBuilder authServerUrl(String authServerUrl) {
        return builder().authServerUrl(authServerUrl);
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder populated with documented default values and the provided client
     * registration path.
     *
     * @param registrationPath {@link #registrationPath()}
     * @return OidcTenantConfigBuilder builder
     */
    public static OidcTenantConfigBuilder registrationPath(String registrationPath) {
        return builder().registrationPath(registrationPath);
    }

    /**
     * Creates {@link OidcTenantConfigBuilder} builder populated with documented default values and the provided token path.
     *
     * @param tokenPath {@link #tokenPath()}
     * @return OidcTenantConfigBuilder builder
     */
    public static OidcTenantConfigBuilder tokenPath(String tokenPath) {
        return builder().tokenPath(tokenPath);
    }

}
