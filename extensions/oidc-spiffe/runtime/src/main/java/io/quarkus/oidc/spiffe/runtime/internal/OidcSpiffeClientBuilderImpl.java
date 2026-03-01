package io.quarkus.oidc.spiffe.runtime.internal;

import java.util.List;

import io.quarkus.oidc.common.runtime.SpiffeJwtSvidClientAssertionProvider.SpiffeClient;
import io.quarkus.oidc.common.runtime.SpiffeJwtSvidClientAssertionProvider.SpiffeClientBuilder;
import io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig;
import io.vertx.core.Vertx;

/**
 * CDI bean that creates {@link SpiffeClient} instances from per-tenant SPIFFE configuration.
 */
final class OidcSpiffeClientBuilderImpl implements SpiffeClientBuilder {

    private final Vertx vertx;

    OidcSpiffeClientBuilderImpl(Vertx vertx) {
        this.vertx = vertx;
    }

    @Override
    public SpiffeClient build(OidcClientCommonConfig.Credentials.Spiffe spiffeConfig) {
        String socketPath = spiffeConfig.endpointSocket()
                .orElseGet(() -> System.getenv("SPIFFE_ENDPOINT_SOCKET"));

        if (socketPath == null || socketPath.isBlank()) {
            throw new IllegalStateException(
                    "SPIFFE Workload API endpoint socket is not configured. Set 'quarkus.oidc.credentials.spiffe.endpoint-socket' "
                            + "or the SPIFFE_ENDPOINT_SOCKET environment variable.");
        }

        List<String> audience = spiffeConfig.audience()
                .filter(l -> !l.isEmpty())
                .orElseThrow(() -> new IllegalStateException(
                        "At least one audience must be configured via 'quarkus.oidc.credentials.spiffe.audience'."));

        String spiffeId = spiffeConfig.spiffeId().orElse(null);

        return new OidcSpiffeClientImpl(vertx, socketPath, audience, spiffeId);
    }
}
