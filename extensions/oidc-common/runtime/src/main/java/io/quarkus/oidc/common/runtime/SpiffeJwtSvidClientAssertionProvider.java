package io.quarkus.oidc.common.runtime;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logging.Logger;

import io.quarkus.arc.Arc;
import io.quarkus.oidc.common.runtime.config.OidcClientCommonConfig;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

/**
 * Client assertion provider that fetches JWT-SVIDs from the SPIFFE Workload API.
 * The actual gRPC call is delegated to a {@link SpiffeClient} built by a {@link SpiffeClientBuilder},
 * which is provided by the {@code quarkus-oidc-spiffe} extension.
 *
 * The initial fetch and all refreshes are fully asynchronous. {@link #getClientAssertion()} is non-blocking
 * and returns the cached token. The periodic timer refreshes the token at 85% of its TTL.
 */
public final class SpiffeJwtSvidClientAssertionProvider implements ClientAssertionProvider {

    private record CachedAssertion(String token, long expiresAt, long timerId) {
    }

    private static final Logger LOG = Logger.getLogger(SpiffeJwtSvidClientAssertionProvider.class);
    private final Vertx vertx;
    private final SpiffeClient spiffeClient;
    private volatile CachedAssertion cachedAssertion;

    private SpiffeJwtSvidClientAssertionProvider(Vertx vertx, OidcClientCommonConfig.Credentials.Spiffe spiffeConfig) {
        this.vertx = vertx;
        SpiffeClientBuilder builder = Arc.container().select(SpiffeClientBuilder.class).get();
        this.spiffeClient = builder.build(spiffeConfig);
    }

    static Uni<SpiffeJwtSvidClientAssertionProvider> create(Vertx vertx,
            OidcClientCommonConfig.Credentials.Spiffe spiffeConfig) {
        SpiffeJwtSvidClientAssertionProvider provider = new SpiffeJwtSvidClientAssertionProvider(vertx, spiffeConfig);
        return provider.fetchAndCache()
                .map(ignored -> provider);
    }

    @Override
    public String getClientAssertion() {
        CachedAssertion current = this.cachedAssertion;
        return current == null ? null : current.token;
    }

    @Override
    public void close() {
        cancelRefresh();
        cachedAssertion = null;
    }

    private Uni<Void> fetchAndCache() {
        return spiffeClient.fetchJwtSvid()
                .onItem().invoke(token -> {
                    if (token == null || token.isBlank()) {
                        LOG.error("SPIFFE client returned an empty JWT-SVID");
                        return;
                    }
                    Long expiresAt = getExpiresAt(token);
                    if (expiresAt == null) {
                        LOG.error("JWT-SVID token or its expiry claim is invalid");
                        return;
                    }
                    cancelRefresh();
                    cachedAssertion = new CachedAssertion(token, expiresAt, scheduleRefresh(expiresAt));
                })
                .onFailure().invoke(t -> LOG.error("Failed to fetch JWT-SVID from SPIFFE Workload API", t))
                .onFailure().recoverWithNull()
                .replaceWithVoid();
    }

    private long scheduleRefresh(long expiresAt) {
        long nowSecs = System.currentTimeMillis() / 1000;
        long ttlMs = (expiresAt - nowSecs) * 1000;
        // refresh at 85% of TTL
        long delay = (long) (ttlMs * 0.85);
        return vertx.setTimer(delay, new Handler<Long>() {
            @Override
            public void handle(Long ignored) {
                fetchAndCache().subscribe().with(
                        v -> LOG.debug("SPIFFE JWT-SVID refreshed"),
                        t -> LOG.error("Failed to refresh SPIFFE JWT-SVID", t));
            }
        });
    }

    private void cancelRefresh() {
        if (cachedAssertion != null) {
            vertx.cancelTimer(cachedAssertion.timerId);
        }
    }

    private static Long getExpiresAt(String token) {
        JsonObject claims = OidcCommonUtils.decodeJwtContent(token);
        if (claims == null || !claims.containsKey(Claims.exp.name())) {
            return null;
        }
        try {
            return claims.getLong(Claims.exp.name());
        } catch (IllegalArgumentException ex) {
            LOG.debug("JWT-SVID expiry claim cannot be converted to Long");
            return null;
        }
    }

    /**
     * Interface for fetching JWT-SVIDs from the SPIFFE Workload API.
     * Implemented by the {@code quarkus-oidc-spiffe} extension.
     */
    public interface SpiffeClient {

        /**
         * Fetches a JWT-SVID token from the SPIFFE Workload API via gRPC.
         *
         * @return a Uni emitting the encoded JWT-SVID token
         */
        Uni<String> fetchJwtSvid();
    }

    /**
     * Builder for creating {@link SpiffeClient} instances from per-tenant SPIFFE configuration.
     * Implemented by the {@code quarkus-oidc-spiffe} extension.
     */
    public interface SpiffeClientBuilder {

        SpiffeClient build(OidcClientCommonConfig.Credentials.Spiffe spiffeConfig);
    }
}
