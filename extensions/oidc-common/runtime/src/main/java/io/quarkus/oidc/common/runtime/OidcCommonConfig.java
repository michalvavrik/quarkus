package io.quarkus.oidc.common.runtime;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

public abstract class OidcCommonConfig implements io.quarkus.oidc.common.runtime.config.OidcCommonConfig {

    private final io.quarkus.oidc.common.runtime.config.OidcCommonConfig mapping;

    protected OidcCommonConfig(io.quarkus.oidc.common.runtime.config.OidcCommonConfig mapping) {
        this.mapping = Objects.requireNonNull(mapping);
    }

    @Override
    public Optional<String> authServerUrl() {
        return mapping.authServerUrl();
    }

    @Override
    public String discoveryPath() {
        return mapping.discoveryPath();
    }

    @Override
    public Optional<Boolean> discoveryEnabled() {
        return mapping.discoveryEnabled();
    }

    @Override
    public Optional<String> registrationPath() {
        return mapping.registrationPath();
    }

    @Override
    public Optional<Duration> connectionDelay() {
        return mapping.connectionDelay();
    }

    @Override
    public int connectionRetryCount() {
        return mapping.connectionRetryCount();
    }

    @Override
    public Duration connectionTimeout() {
        return mapping.connectionTimeout();
    }

    @Override
    public boolean useBlockingDnsLookup() {
        return mapping.useBlockingDnsLookup();
    }

    @Override
    public OptionalInt maxPoolSize() {
        return mapping.maxPoolSize();
    }

    @Override
    public boolean followRedirects() {
        return mapping.followRedirects();
    }

    @Override
    public io.quarkus.oidc.common.runtime.config.OidcCommonConfig.Proxy proxy() {
        return mapping.proxy();
    }

    @Override
    public io.quarkus.oidc.common.runtime.config.OidcCommonConfig.Tls tls() {
        return mapping.tls();
    }
}
