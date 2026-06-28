package io.quarkus.spiffe.client.runtime.internal;

import io.quarkus.spiffe.client.api.JwtSvid;
import io.quarkus.spiffe.client.api.JwtSvidRequest;
import io.quarkus.spiffe.client.api.SpiffeClient;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Vertx;

/**
 * This SPIFFE client implementation is registered as a CDI bean.
 */
final class SpiffeClientImpl implements SpiffeClient {

    private final String endpointSocket;
    private final Vertx vertx;

    SpiffeClientImpl(SpiffeClientConfig config, Vertx vertx) {
        this.endpointSocket = config.endpointSocket().orElseThrow(() -> new IllegalStateException(
                "The 'quarkus.spiffe-client.endpoint-socket' configuration property is not set"));
        this.vertx = vertx;
    }

    @Override
    public Uni<JwtSvid> fetchJwtSvid(JwtSvidRequest request) {
        // FIXME: impl. me!
        return Uni.createFrom().nullItem();
    }

    @Override
    public Multi<JwtSvid> fetchJwtSvids(JwtSvidRequest request) {
        // FIXME: impl. me!
        return Multi.createFrom().nothing();
    }
}
