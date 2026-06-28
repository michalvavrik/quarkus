package io.quarkus.spiffe.client.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.spiffe-client")
@ConfigRoot
interface SpiffeClientBuildTimeConfig {

    /**
     * If SPIFFE Workload API client is enabled.
     */
    @WithDefault("true")
    boolean enabled();

    /**
     * SPIFFE Dev Services config.
     */
    DevServices devservices();

    /**
     * SPIFFE Dev Services config.
     */
    interface DevServices {

        /**
         * Flag to enable (default) or disable Dev Services.
         */
        @WithDefault("true")
        boolean enabled();

        /**
         * Transport protocol for the SPIFFE Workload API server.
         */
        @WithDefault("unix")
        Transport transport();

        enum Transport {
            TCP,
            UNIX
        }

    }
}
