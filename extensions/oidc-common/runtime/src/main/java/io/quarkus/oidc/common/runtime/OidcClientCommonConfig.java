package io.quarkus.oidc.common.runtime;

import java.util.Optional;

public abstract class OidcClientCommonConfig extends OidcCommonConfig
        implements io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig {

    private final io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig mapping;

    protected OidcClientCommonConfig(io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig mapping) {
        super(mapping);
        this.mapping = mapping;
    }

    @Override
    public Optional<String> tokenPath() {
        return mapping.tokenPath();
    }

    @Override
    public Optional<String> revokePath() {
        return mapping.revokePath();
    }

    @Override
    public Optional<String> clientId() {
        return mapping.clientId();
    }

    @Override
    public Optional<String> clientName() {
        return mapping.clientName();
    }

    @Override
    public io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig.Credentials credentials() {
        return mapping.credentials();
    }
}
