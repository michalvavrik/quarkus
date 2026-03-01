package io.quarkus.oidc.spiffe.runtime.internal;

import java.util.List;
import java.util.concurrent.Executor;

import org.jboss.logging.Logger;

import io.grpc.CallCredentials;
import io.grpc.Channel;
import io.grpc.Metadata;
import io.grpc.stub.StreamObserver;
import io.quarkus.oidc.common.runtime.SpiffeJwtSvidClientAssertionProvider;
import io.quarkus.oidc.spiffe.runtime.internal.grpc.JWTSVIDRequest;
import io.quarkus.oidc.spiffe.runtime.internal.grpc.JWTSVIDResponse;
import io.quarkus.oidc.spiffe.runtime.internal.grpc.SpiffeWorkloadAPIGrpc;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Vertx;
import io.vertx.core.net.SocketAddress;
import io.vertx.grpc.client.GrpcClient;
import io.vertx.grpc.client.GrpcClientChannel;

/**
 * SPIFFE Workload API gRPC client that fetches JWT-SVIDs asynchronously.
 */
final class OidcSpiffeClientImpl implements SpiffeJwtSvidClientAssertionProvider.SpiffeClient {

    private static final Logger LOG = Logger.getLogger(OidcSpiffeClientImpl.class);
    private static final Metadata.Key<String> SECURITY_HEADER_KEY = Metadata.Key.of("workload.spiffe.io",
            Metadata.ASCII_STRING_MARSHALLER);

    private final SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub stub;
    private final List<String> audience;
    private final String spiffeId;

    OidcSpiffeClientImpl(Vertx vertx, String socketPath, List<String> audience, String spiffeId) {
        this.audience = audience;
        this.spiffeId = spiffeId;
        GrpcClient grpcClient = GrpcClient.client(vertx);
        Channel channel = new GrpcClientChannel(grpcClient, SocketAddress.domainSocketAddress(socketPath));
        this.stub = SpiffeWorkloadAPIGrpc.newStub(channel)
                .withCallCredentials(new CallCredentials() {
                    @Override
                    public void applyRequestMetadata(RequestInfo requestInfo, Executor appExecutor,
                            MetadataApplier applier) {
                        Metadata metadata = new Metadata();
                        metadata.put(SECURITY_HEADER_KEY, "true");
                        applier.apply(metadata);
                    }
                });
    }

    @Override
    public Uni<String> fetchJwtSvid() {
        JWTSVIDRequest.Builder requestBuilder = JWTSVIDRequest.newBuilder().addAllAudience(audience);
        if (spiffeId != null) {
            requestBuilder.setSpiffeId(spiffeId);
        }

        return Uni.createFrom().emitter(emitter -> stub.fetchJWTSVID(requestBuilder.build(),
                new StreamObserver<>() {
                    @Override
                    public void onNext(JWTSVIDResponse response) {
                        if (response.getSvidsCount() == 0) {
                            LOG.error("SPIFFE Workload API returned no JWT-SVIDs");
                            emitter.complete(null);
                        } else {
                            emitter.complete(response.getSvids(0).getSvid());
                        }
                    }

                    @Override
                    public void onError(Throwable t) {
                        emitter.fail(t);
                    }

                    @Override
                    public void onCompleted() {
                    }
                }));
    }
}
