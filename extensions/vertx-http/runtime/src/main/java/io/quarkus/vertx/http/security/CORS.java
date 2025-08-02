package io.quarkus.vertx.http.security;

import io.quarkus.vertx.http.runtime.cors.CORSConfig;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.common.annotation.Experimental;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

@Experimental("This API is currently experimental and might get changed")
public sealed interface CORS permits CORS.Builder.CORSImpl {

    CORSConfig config();

    static Builder builder() {
        return new Builder();
    }

    static CORS origins(String... origins) {
        Objects.requireNonNull(origins, "Origins must not be null");
        return origins(List.of(origins));
    }

    static CORS origins(List<String> origins) {
        return builder().origins(origins).build();
    }

    final class Builder {

        private Optional<Boolean> accessControlAllowCredentials;
        private Optional<Duration> accessControlMaxAge;
        private Optional<List<String>> exposedHeaders;
        private Optional<List<String>> headers;
        private Optional<List<String>> methods;
        private Optional<List<String>> origins;

        public Builder() {
            this(HttpSecurityUtils.getDefaultVertxHttpConfig().cors());
        }

        public Builder(CORSConfig corsConfig) {
            this.accessControlAllowCredentials = corsConfig.accessControlAllowCredentials();
            this.accessControlMaxAge = corsConfig.accessControlMaxAge();
            this.exposedHeaders = corsConfig.exposedHeaders();
            this.headers = corsConfig.headers();
            this.methods = corsConfig.methods();
            this.origins = corsConfig.origins();
        }

        public Builder accessControlMaxAge(Duration accessControlMaxAge) {
            Objects.requireNonNull(accessControlMaxAge, "accessControlMaxAge argument must not be null");
            this.accessControlMaxAge = Optional.of(accessControlMaxAge);
            return this;
        }

        public Builder accessControlAllowCredentials() {
            return accessControlAllowCredentials(true);
        }

        public Builder accessControlAllowCredentials(boolean accessControlAllowCredentials) {
            this.accessControlAllowCredentials = Optional.of(accessControlAllowCredentials);
            return this;
        }

        public Builder exposedHeader(String exposedHeader) {
            if (exposedHeader == null) {
                throw new IllegalArgumentException("Argument 'exposedHeader' cannot be null");
            }
            return exposedHeaders(List.of(exposedHeader));
        }

        public Builder exposedHeaders(String... exposedHeaders) {
            if (exposedHeaders == null || exposedHeaders.length == 0) {
                throw new IllegalArgumentException("No exposed headers specified");
            }
            return builder().exposedHeaders(List.of(exposedHeaders));
        }

        public Builder exposedHeaders(List<String> exposedHeaders) {
            this.exposedHeaders = merge(this.exposedHeaders, exposedHeaders, "Exposed headers");
            return this;
        }

        public Builder header(String header) {
            if (header == null) {
                throw new IllegalArgumentException("Argument 'header' cannot be null");
            }
            return headers(List.of(header));
        }

        public Builder headers(String... headers) {
            if (headers == null || headers.length == 0) {
                throw new IllegalArgumentException("No headers specified");
            }
            return builder().headers(List.of(headers));
        }

        public Builder headers(List<String> newHeaders) {
            this.headers = merge(this.headers, newHeaders, "Headers");
            return this;
        }

        public Builder method(String method) {
            if (method == null) {
                throw new IllegalArgumentException("Argument 'method' cannot be null");
            }
            return methods(List.of(method));
        }

        public Builder methods(String... methods) {
            if (methods == null || methods.length == 0) {
                throw new IllegalArgumentException("No methods specified");
            }
            return builder().methods(List.of(methods));
        }

        public Builder methods(List<String> newMethods) {
            this.methods = merge(this.methods, newMethods, "Methods");
            return this;
        }

        public Builder origin(String origin) {
            if (origin == null) {
                throw new IllegalArgumentException("Argument 'origin' cannot be null");
            }
            return origins(List.of(origin));
        }

        public Builder origins(String... origins) {
            if (origins == null || origins.length == 0) {
                throw new IllegalArgumentException("No origins specified");
            }
            return builder().origins(List.of(origins));
        }

        public Builder origins(List<String> newOrigins) {
            this.origins = merge(this.origins, newOrigins, "Origins");
            return this;
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

        private static Optional<List<String>> merge(Optional<List<String>> optionalOriginalList, List<String> newList, String what) {
            if (newList == null) {
                throw new IllegalArgumentException(what + " must not be null");
            }
            if (newList.isEmpty()) {
                return optionalOriginalList;
            }
            final List<String> result;
            if (optionalOriginalList.orElse(List.of()).isEmpty()) {
                result = List.copyOf(newList);
            } else {
                result = Stream.concat(optionalOriginalList.get().stream(), newList.stream()).toList();
            }
            return Optional.of(result);
        }

        private record CORSImpl(CORSConfig config) implements CORS {
        }
    }
}
