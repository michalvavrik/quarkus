package io.quarkus.vertx.http.security;

import io.quarkus.vertx.http.runtime.cors.CORSConfig;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.common.annotation.Experimental;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

@Experimental("This API is currently experimental and might get changed")
public sealed interface CORS permits CORS.Builder.CORSImpl {

    CORSConfig config();

    static Builder builder() {
        return new Builder();
    }

    static Builder builder(List<String> origins) {
        return builder().origins(origins);
    }

    final class Builder {

        private final Optional<Boolean> accessControlAllowCredentials;
        private final Optional<Duration> accessControlMaxAge;
        private final Optional<List<String>> exposedHeaders;
        private final Optional<List<String>> headers;
        private final Optional<List<String>> methods;
        private final Optional<List<String>> origins;

        public Builder() {
            this(getDefaultConfig());
        }

        public Builder(CORSConfig corsConfig) {
            this.accessControlAllowCredentials = corsConfig.accessControlAllowCredentials();
            this.accessControlMaxAge = corsConfig.accessControlMaxAge();
            this.exposedHeaders = corsConfig.exposedHeaders();
            this.headers = corsConfig.headers();
            this.methods = corsConfig.methods();
            this.origins = corsConfig.origins();
        }

        public Builder origins(List<String> origins) {
            // FIXME: impl. me!
            return null;
        }

        public CORS build() {
            record CORSConfigImpl(Optional<Boolean> accessControlAllowCredentials, Optional<Duration> accessControlMaxAge,
                                  Optional<List<String>> exposedHeaders, Optional<List<String>> headers,
                                  Optional<List<String>> methods, Optional<List<String>> origins) implements CORSConfig {
                @Override
                public boolean enabled() {
                    return true;
                }
            }
            return new CORSImpl(new CORSConfigImpl(accessControlAllowCredentials, accessControlMaxAge, exposedHeaders,
                    headers, methods, origins));
        }

        private static CORSConfig getDefaultConfig() {
            return HttpSecurityUtils.getDefaultVertxHttpConfig().cors();
        }

        private record CORSImpl(CORSConfig config) implements CORS {

        }
    }
}
