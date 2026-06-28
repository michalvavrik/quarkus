package io.quarkus.spiffe.client.runtime.internal;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithConverter;

/**
 * Configuration for the SPIFFE Workload API client.
 */
@ConfigMapping(prefix = "quarkus.spiffe-client")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface SpiffeClientConfig {

    /**
     * SPIFFE Workload Endpoint socket URI. Supports {@code unix://} for Unix Domain Socket
     * and {@code tcp://} for TCP transport as defined by the
     * <a href="https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_Endpoint.md">SPIFFE Workload
     * Endpoint</a> specification.
     * <p>
     * Examples: {@code unix:///run/spire/sockets/agent.sock}, {@code tcp://127.0.0.1:8080}
     */
    Optional<@WithConverter(SpiffeEndpointSocketConverter.class) String> endpointSocket();
}
