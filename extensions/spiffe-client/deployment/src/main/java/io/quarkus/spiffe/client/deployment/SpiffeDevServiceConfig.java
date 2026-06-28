package io.quarkus.spiffe.client.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.spiffe-client.devservices")
@ConfigRoot
interface SpiffeDevServiceConfig {

    /**
     * Transport protocol for the fake SPIFFE Workload API server.
     */
    @WithDefault("unix")
    Transport transport();

    enum Transport {
        TCP,
        UNIX
    }
}
