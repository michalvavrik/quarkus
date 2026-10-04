package io.quarkus.spiffe.client.runtime.internal;

import java.security.KeyStore;
import java.time.Duration;
import java.util.Optional;

import javax.net.ssl.SSLContext;

import io.quarkus.tls.TlsConfiguration;
import io.vertx.core.net.ClientSSLOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.SSLEngineOptions;
import io.vertx.core.net.ServerSSLOptions;
import io.vertx.core.net.TrustOptions;

abstract class SpiffeBaseTlsConfiguration implements TlsConfiguration {

    // TODO: validate reload period is lower than svid ttl
    // TODO: validate reload period correct period during the build time
    // TODO: validate that tls config of this name is not configured by user otherwise fail
    // TODO: validate TLS registry present or fail build
    // TODO: ensure all methods are enforcing spiffe id authorization check

    protected abstract String getTlsConfigurationName();

    protected abstract Duration getReloadPeriod();

    protected abstract String getSpiffeId();

    @Override
    public final String getName() {
        return getTlsConfigurationName();
    }

    @Override
    public final Optional<SSLEngineOptions> getSslEngineOptions() {
        // TODO: impl. me!
        return Optional.empty();
    }

    @Override
    public final boolean reload() {
        // TODO: impl. me!
        return false;
    }

    @Override
    public final boolean usesSni() {
        return false;
    }

    @Override
    public final Optional<String> getHostnameVerificationAlgorithm() {
        return Optional.of("NONE");
    }

    @Override
    public final boolean isTrustAll() {
        return false;
    }

    @Override
    public final SSLContext createSSLContext() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public final ClientSSLOptions getClientSSLOptions() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public final ServerSSLOptions getServerSSLOptions() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public final TrustOptions getTrustStoreOptions() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public final KeyStore getTrustStore() {
        throw new UnsupportedOperationException(
                "SPIFFE X.509-SVID TLS configurations do not expose a raw trust store, as it cannot enforce "
                        + "SPIFFE ID authorization; use getTrustStoreOptions() instead.");
    }

    @Override
    public final KeyCertOptions getKeyStoreOptions() {
        // TODO: impl. me!
        return null;
    }

    @Override
    public final KeyStore getKeyStore() {
        throw new UnsupportedOperationException(
                "SPIFFE X.509-SVID TLS configurations do not expose a raw key store, as consumers of it build their own "
                        + "TLS context that skips SPIFFE ID authorization; use getKeyStoreOptions() instead.");
    }
}
