package io.quarkus.spiffe.client.runtime.internal;

import io.quarkus.spiffe.client.api.SpiffeClient;
import io.vertx.core.Vertx;

public final class SpiffeClientBuilder {

    private String endpointSocket;
    private Vertx vertx;

    public SpiffeClientBuilder endpointSocket(String endpointSocket) {
        this.endpointSocket = endpointSocket;
        return this;
    }

    public SpiffeClientBuilder vertx(Vertx vertx) {
        this.vertx = vertx;
        return this;
    }

    public SpiffeClient build() {
        // TODO: implement the Vert.x gRPC Workload API client and close resources on shutdown
        return null;
    }
}
